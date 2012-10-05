{-# LANGUAGE CPP #-}
#if PRODUCTION
{-# LANGUAGE Safe #-}
#endif
{-# LANGUAGE OverloadedStrings, DeriveDataTypeable #-}
{-# LANGUAGE MultiParamTypeClasses, IncoherentInstances, FlexibleContexts #-}
{-# LANGUAGE TypeSynonymInstances, FlexibleInstances, ScopedTypeVariables #-}
-- | This module export the core gitstar model and types.
module Gitstar.Policy ( GitstarPolicy
                      , withGitstar
                      -- * Projects
                      , ProjectName, ProjectId, Project(..), Public(..)
                      , mkProject, updateUserWithProjId, partialProjectUpdate
                      , GitstarApp(..)
                      -- * Users
                      , UserName, Url, User(..), SSHKey(..)
                      , getOrCreateUser, partialUserUpdate
                      , delUserKey, addUserKey
                      -- * HTTP access to git API
                      , gitstarRepoHttp
                      ) where

import Prelude hiding (lookup)
import Config

import Control.Monad

import qualified Data.Bson as B
import Data.Bson.Binary
import Data.Binary.Get
import Data.List (isInfixOf)
import Data.Typeable
import Data.Maybe (fromMaybe)
import Hails.Data.Hson
import Hails.HttpServer
import Hails.Database
import Hails.Database.Structured
import Hails.HttpClient as C
import Hails.PolicyModule
import Hails.PolicyModule.DSL

import qualified Data.Text as T

import LIO
import LIO.DCLabel
import Gitstar.Models

-- | Internal gitstar policy. The type constructor should not be
-- exported as to avoid leaking the privilege.
data GitstarPolicy = GitstarPolicyP DCPriv
  deriving (Typeable)

instance PolicyModule GitstarPolicy where
  initPolicyModule priv = do
    let this = privDesc priv
    setPolicy priv $ do
      database $ do
        readers ==> anybody
        writers ==> anybody
        admins  ==> this

      collection "projects" $ do
        access $ do
          readers ==> anybody
          writers ==> anybody
        clearance $ do
          secrecy ==> this
          integrity ==> anybody
        document $ \doc -> do
          readers ==>
            let (Right proj) = fromDocument doc
            in case projectReaders proj of
              Left Public -> anybody
              Right rs ->
                let writers = map T.unpack $ (projectOwner proj):(rs ++ projectCollaborators proj)
                in foldl (\/) this writers
          writers ==>
            let (Just proj) = fromDocument doc
            in (T.unpack $ projectOwner proj) \/ this
        field "name" searchable
        field "owner" searchable

      collection "users" $ do
        access $ do
          readers ==> anybody
          writers ==> anybody
        clearance $ do
          secrecy ==> this
          integrity ==> anybody
        document $ \doc -> do
          readers ==> anybody
          writers ==>
            let (Right user) = fromDocument doc
            in this \/ (T.unpack $ userName user)
        field "keys" searchable

      collection "apps" $ do
        access $ do
          readers ==> anybody
          writers ==> anybody
        clearance $ do
          secrecy ==> this
          integrity ==> anybody
        document $ \doc -> do
          let (Right app) = fromDocument doc
          readers ==> anybody
          writers ==> this \/ (T.unpack $ appOwner app)
        field "name" searchable
    return $ GitstarPolicyP priv

withGitstar :: MonadLIO DCLabel m => DBAction a -> m a
withGitstar act = liftLIO $ withPolicyModule $ \(_ :: GitstarPolicy) -> act


instance DCLabeledRecord GitstarPolicy User where
  endorseInstance _ = GitstarPolicyP undefined

instance DCLabeledRecord GitstarPolicy Project where
  endorseInstance _ = GitstarPolicyP undefined

--
-- User related
--

partialUserUpdate :: MonadLIO DCLabel m => UserName -> DCLabeled Document -> m (DCLabeled User)
partialUserUpdate uName ldoc = liftLIO $ do
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    doc <- unlabel ldoc
    method <- lookup "_method" doc
    when (method /= ("PUT" :: String)) $ fail "_method must be PUT"
    user0 <- getOrCreateUser uName
    let user = user0 { userFullName = lookup "full_name" doc
                     , userCity = lookup "city" doc
                     , userWebsite = lookup "website" doc
                     , userGravatar = lookup "gravatar" doc }
    let lbl = (labelOf ldoc) {
                dcIntegrity = (dcIntegrity lbl) \/ (privDesc priv) }
    labelP priv lbl user

getOrCreateUser :: MonadLIO DCLabel m => UserName -> m User
getOrCreateUser username = liftLIO $ withPolicyModule $ \(GitstarPolicyP priv) -> do
  muser <- (find $ select [ "_id" -: username ] "users") >>= next
  case muser of
    Just luser -> do
      user <- unlabel luser
      fromDocument user
    Nothing -> do
      let user = User username [] [] Nothing Nothing Nothing Nothing
      insertP_ priv "users" (toDocument user)
      return user

delUserKey :: MonadLIO DCLabel m => UserName -> DCLabeled Document -> m (DCLabeled User)
delUserKey uName ldoc = liftLIO $ do
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    doc <- unlabel ldoc
    method <- lookup "_method" doc
    when (method /= ("DELETE" :: String)) $ fail "_method must be DELETE"
    kid <- lookup "_id" doc
    user <- getOrCreateUser uName
    let keys = filter (\k -> (show $ sshKeyId k) /= kid) $ userKeys user
    let lbl = labelOf ldoc
    labelP priv (lbl { dcIntegrity = (dcIntegrity lbl) \/ (privDesc priv) }) $
                user { userKeys = (keys :: [SSHKey]) }

addUserKey :: MonadLIO DCLabel m => UserName -> DCLabeled Document -> m (DCLabeled User)
addUserKey uName ldoc = liftLIO $ do
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    (Right key0) <- (sshKeyFromDocument . hsonDocToBsonDoc) `liftM` unlabel ldoc
    objId <- genObjectId
    let key = key0 { sshKeyId = Just objId }
    user <- getOrCreateUser uName
    let lbl = labelOf ldoc
    labelP priv (lbl { dcIntegrity = (dcIntegrity lbl) \/ (privDesc priv) }) $
                user { userKeys = (key:userKeys user) }

--
-- Project related
--
mkProject :: MonadLIO DCLabel m => UserName -> DCLabeled Document -> m (DCLabeled Project)
mkProject owner ldoc = liftLIO $ do
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    doc <- unlabel ldoc
    let (Right proj) = fromDocument $ ("owner" -: owner):doc
        lbl = labelOf ldoc
    labelP priv (lbl { dcIntegrity = (dcIntegrity lbl) \/ (privDesc priv) }) $
                proj

partialProjectUpdate :: MonadLIO DCLabel m
                     => UserName
                     -> ProjectName
                     -> DCLabeled Document
                     -> m (DCLabeled Project)
partialProjectUpdate uName projName ldoc = liftLIO $
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    doc <- unlabel ldoc
    (Just proj0) <- findWhere $
      select ["owner" -: uName, "name" -: projName] "projects"
    let proj = proj0 {
                  projectDescription = fromMaybe (projectDescription proj0) $ lookup "description" doc
                }
    let lbl0 = labelOf ldoc
    let lbl = lbl0 { dcIntegrity = (dcIntegrity lbl0) \/ (privDesc priv) }
    labelP priv lbl proj

-- | Given a user name and project ID, associate the project with the
-- user, if it's not already.
updateUserWithProjId :: MonadLIO DCLabel m => UserName -> ProjectId -> m ()
updateUserWithProjId username oid = liftLIO $ withPolicyModule $ \(GitstarPolicyP priv) -> do
  muser <- findBy "users" "_id" username
  mproj <- findBy "projects" "_id" oid
  case (muser, mproj) of
    (Just usr, Just proj) -> do
      unless (username == projectOwner proj) $ fail "User is not project owner"
      let projIds = userProjects usr
          newUser = usr { userProjects = oid : projIds }
      when (oid `notElem` projIds) $ void $ saveRecordP priv newUser
    _ -> fail  "Expected valid user and project"

--
-- Repo related
--

-- | Given user name, project name and URL suffix make GET request 
-- to gitstar-ssh-web server. This is the low-lever interface to
-- accessing git objects.
-- The request made will be: @GET /repos/usr/proj/urlSuffix@
gitstarRepoHttp :: UserName
                -> ProjectName
                -> Url
                -> DC (Maybe B.Document)
gitstarRepoHttp usr proj urlSuffix = do
  -- Make sure current user can read:
  mProj  <- withGitstar $ do
              cur <- find $ select [ "name"  -: proj
                            , "owner" -: usr ] "projects"
              next cur
  when (".." `isInfixOf` (T.unpack urlSuffix)) $ throwLIO . userError $
    "gitstarRepoHttp: Path must be fully expanded"
  case mProj of
    Nothing -> return Nothing
    Just _ -> do
       let url = T.concat
                  [ gitstar_ssh_web_url , "repos/" , usr , "/"
                  , proj, urlSuffix]
       sshResp <- simpleGetHttp (T.unpack url)
       if respStatus sshResp /= status200
         then return Nothing
         else return . Just $ runGet getDocument $ respBody sshResp

