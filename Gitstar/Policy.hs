{-# LANGUAGE Trustworthy #-}
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
                let rds = map T.unpack $ (projectOwner proj):"gitstar":(rs ++ projectCollaborators proj)
                in foldl (\/) this rds
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

    where anybody = cTrue

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
    doc <- liftLIO $ unlabelP priv ldoc
    method <- lookup "_method" doc
    when (method /= ("PUT" :: String)) $ fail "_method must be PUT"
    luser0 <- getOrCreateLUser uName
    user0 <- liftLIO $ unlabelP priv luser0
    let user = user0 { userFullName = lookup "full_name" doc
                     , userCity = lookup "city" doc
                     , userWebsite = lookup "website" doc
                     , userGravatar = lookup "gravatar" doc }
    let lbl = lub (labelOf luser0) (labelOf ldoc)
    liftLIO $ labelP priv lbl user

getOrCreateLUser :: MonadLIO DCLabel m => UserName -> m (DCLabeled User)
getOrCreateLUser username = liftLIO $ withPolicyModule $ \(GitstarPolicyP priv) -> do
  muser <- (find $ select [ "_id" -: username ] "users") >>= next
  case muser of
    Just luser -> do
      user <- liftLIO $ unlabelP priv luser
      doc <- fromDocument user
      liftLIO $ labelP priv (labelOf luser) doc
    Nothing -> do
      let user = User username [] [] Nothing Nothing Nothing Nothing
      insertP_ priv "users" (toDocument user)
      liftLIO $ label dcPublic user

getOrCreateUser :: MonadLIO DCLabel m => UserName -> m User
getOrCreateUser username = getOrCreateLUser username >>= liftLIO . unlabel

delUserKey :: MonadLIO DCLabel m => UserName -> DCLabeled Document -> m (DCLabeled User)
delUserKey uName ldoc = liftLIO $ do
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    doc <- liftLIO $ unlabel ldoc
    method <- lookup "_method" doc
    when (method /= ("DELETE" :: String)) $ fail "_method must be DELETE"
    kid <- lookup "_id" doc
    user <- getOrCreateUser uName
    let keys = filter (\k -> (show $ sshKeyId k) /= kid) $ userKeys user
    let lbl = labelOf ldoc
    liftLIO $ labelP priv (lbl { dcIntegrity = (dcIntegrity lbl) \/ (privDesc priv) }) $
                          user { userKeys = (keys :: [SSHKey]) }

addUserKey :: MonadLIO DCLabel m => UserName -> DCLabeled Document -> m (DCLabeled User)
addUserKey uName ldoc = liftLIO $ do
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    (Right key0) <- (sshKeyFromDocument . hsonDocToBsonDoc)
                      `liftM` (liftLIO $ unlabel ldoc)
    objId <- genObjectId
    let key = key0 { sshKeyId = Just objId }
    user <- getOrCreateUser uName
    let lbl = labelOf ldoc
    liftLIO $ labelP priv (lbl { dcIntegrity = (dcIntegrity lbl) \/ (privDesc priv) }) $
                user { userKeys = (key:userKeys user) }

--
-- Project related
--
mkProject :: MonadLIO DCLabel m => DCLabeled Document -> m (DCLabeled Project)
mkProject ldoc = liftLIO $ do
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    doc <- liftLIO $ unlabel ldoc
    let (Right proj) = fromDocument $ doc
        lbl = labelOf ldoc
    liftLIO $ labelP priv (lbl { dcIntegrity = (dcIntegrity lbl) \/ (privDesc priv) }) $
                proj

partialProjectUpdate :: MonadLIO DCLabel m
                     => DCLabeled Project
                     -> m (DCLabeled Project)
partialProjectUpdate lproj = liftLIO $
  withPolicyModule $ \(GitstarPolicyP priv) -> do
    projU <- liftLIO $ unlabelP priv lproj
    (Just lprojDoc) <- findOne $
      select ["owner" -: projectOwner projU, "name" -: projectName projU] "projects"
    proj0 <- liftLIO $ unlabelP priv lprojDoc >>= fromDocument
    let proj = projU {
                  projectId = projectId proj0
                }
    let lbl0 = labelOf lproj
    let lbl = lub (labelOf lprojDoc) lbl0
    liftLIO $ labelP priv lbl proj

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

