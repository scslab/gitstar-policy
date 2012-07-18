{-# LANGUAGE OverloadedStrings #-}
module Gitstar.Models (
  -- * Projects model
    ProjectId, ProjectName, Project(..), Public(..), isPublic
  , projectRepository, projectObjId
  -- * App model
  , GitstarApp(..)
  -- * Users
  , UserName, Url, User(..)
  -- * Keys
  , KeyId, SSHKey(..), fingerprint
  ) where

import           Prelude hiding (lookup)

import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.Maybe

import           Hails.Crypto (md5)
import           Hails.Data.LBson hiding ( map, head, break
                                         , tail, words, key, filter
                                         , dropWhile, drop, split, foldl
                                         , notElem, isInfixOf)
import           Hails.Database.MongoDB.Structured


--
-- Projects
--



-- | Project id is simply an object id
type ProjectId = Maybe ObjectId

-- | Project name is simply a stirng
type ProjectName = String

-- | A data type describing a project
data Project = Project {
    projectId            :: ProjectId
    -- ^ Project id
  , projectName          :: ProjectName
    -- ^ Project name
  , projectOwner         :: UserName
    -- ^ Project owner
  , projectDescription   :: String
    -- ^ Project descritption
  , projectCollaborators :: [UserName]
    -- ^ Project collaborators that can read and write to repository
  , projectReaders       :: Either Public [UserName]
    -- ^ Project is either public or private to the readers and
    -- collaborators
  , projectApps          :: [String]
    -- ^ App has a set of associated apps
  , projectForkedFrom    :: Maybe ObjectId
    -- ^ Id of project this project was forked off from, if any.
  } deriving (Show)

-- | Data type denoting public projects
data Public = Public deriving (Show, Read)

-- | Is the project publicly readable.
isPublic :: Project -> Bool
isPublic proj = either (const True) (const False) $ projectReaders proj

-- | Project repository path.
projectRepository :: Project -> String
projectRepository proj = projectOwner proj ++ "/" ++ projectName proj ++ ".git"

-- | get Project id of an already inserted project. Error otherwise
projectObjId :: Project -> ObjectId
projectObjId = fromJust . projectId

instance DCRecord Project where
  fromDocument doc = do
    pName  <- lookup (u "name") doc
    pOwner <- lookup (u "owner") doc
    let pDesc  = fromMaybe "" $ lookup (u "description") doc
        pColls = fromMaybe [] $ lookup (u "collaborators") doc
        pRedrs = fromMaybe [] $ lookup (u "readers") doc
        pPub = case look (u "public") doc of
                Just v | v == (val True) -> True
                       | v == (val ("1" :: String)) -> True
                       | otherwise -> False
                Nothing -> False
        pApps = fromMaybe [] $ lookup (u "apps") doc

    return $ Project
      { projectId            = lookup (u "_id") doc
      , projectName          = pName 
      , projectOwner         = pOwner
      , projectDescription   = pDesc
      , projectCollaborators = pColls
      , projectReaders       = if pPub then
                                Left Public
                                else Right pRedrs
      , projectApps          = pApps
      , projectForkedFrom    = lookup (u "forked_from") doc
      }

  toDocument proj =
    (maybe [] (\i -> [(u "_id") =: i]) $ projectId proj)
    ++
    [ (u "name")          =: projectName proj
    , (u "owner")         =: projectOwner proj
    , (u "description")   =: projectDescription proj
    , (u "collaborators") =: projectCollaborators proj
    , (u "readers")       =: either (const []) id (projectReaders proj)
    , (u "public")        =: either (const True) (const False) (projectReaders proj)
    , (u "apps")          =: projectApps proj
    , (u "forked_from")   =: projectForkedFrom proj]

  collectionName _ = "projects"

instance DCLabeledRecord Project where


--
-- Apps
--

-- | A gitstar app.
data GitstarApp = GitstarApp {
    appId          :: String
  -- ^ Unique name for the app (not displayed to user)
  , appName        :: String
  -- ^ Descriptive name of app (used to search for apps)
  , appTitle       :: String
  -- ^ App title, to be displayed on project tabs
  , appUrl         :: Url
  -- ^ App url, containing @$user@ and @$project@ to be replaced by
  -- current user an app
  , appOwner       :: UserName
  -- ^ App owner
  , appDescription :: String
  -- ^ App description
} deriving (Show)


instance DCRecord GitstarApp where
  collectionName = const "apps"
  fromDocument doc = do
    aId <- lookup (u "_id") doc
    aName <- lookup (u "name") doc
    aTitle <- lookup (u "title") doc
    aUrl  <- lookup (u "url") doc
    aOwner  <- lookup (u "owner") doc
    aDescription <- lookup (u "description") doc
    return $ GitstarApp
      { appId = aId
      , appName = aName
      , appTitle = aTitle
      , appUrl    = aUrl
      , appOwner = aOwner
      , appDescription = aDescription
      }

  toDocument app =
    [ "_id" =: (appId app)
    , "name" =: (appName app)
    , "title" =: (appTitle app)
    , "owner" =: (appOwner app)
    , "description" =: (appDescription app)
    , "url" =: (appUrl app)]

--
-- Users
--

-- | User name is simply  a stirng
type UserName = String

-- | Email address of a user
type Email = String

-- | URL
type Url = String

-- | Data type describing users
data User = User { userName     :: UserName     -- ^ Username
                 , userKeys     :: [SSHKey]     -- ^ User's ssh keys
                 , userProjects :: [ProjectId]  -- ^ User's projects
                 , userFullName :: Maybe String -- ^ User's full name
                 , userCity     :: Maybe String -- ^ User's location
                 , userWebsite  :: Maybe Url    -- ^ User's website
                 , userGravatar :: Maybe Email  -- ^ User's gravatar e-mail
                 } deriving (Show, Eq)

instance DCRecord User where
  fromDocument doc = do
    uName   <- lookup (u "_id") doc
    keyDocs <- lookup (u "keys") doc
    keys <- case mapM safeFromBsonDoc keyDocs of
               Nothing -> fail "fromDocument: safeFromBsonDoc failed"
               Just ks -> mapM fromDocument ks
    uPrjs <- lookup (u "projects") doc
    return $ User { userName      = uName
                  , userKeys      = keys
                  , userProjects  = uPrjs
                  , userFullName = lookup (u "full_name") doc
                  , userCity = lookup (u "city") doc
                  , userWebsite = lookup (u "website") doc
                  , userGravatar = lookup (u "gravatar") doc}

  toDocument usr = [ (u "_id")       =: userName usr
                   , (u "keys")      =: (map sshKeyToDoc $ userKeys usr)
                   , (u "projects")  =: userProjects usr
                   , (u "full_name") =: userFullName usr
                   , (u "city")      =: userCity usr
                   , (u "website")   =: userWebsite usr
                   , (u "gravatar")  =: userGravatar usr]
    where sshKeyToDoc = (fromJust . safeToBsonDoc . toDocument)
  collectionName _ = "users"

instance DCLabeledRecord User where

--
-- Keys
--

-- | A key id is an object ID
type KeyId = ObjectId

-- | An SSH key has a name and key value
data SSHKey = SSHKey { sshKeyId    :: KeyId    -- ^ Key id
                     , sshKeyTitle :: !String  -- ^ Name
                     , sshKeyValue :: !Binary  -- ^ Actual key
                     } deriving (Show, Eq)

instance DCRecord SSHKey where
  fromDocument doc = do
    i <- lookup (u "_id") doc
    t <- lookup (u "title") doc
    v <- lookup (u "value")  doc
    return SSHKey { sshKeyId = i
                  , sshKeyTitle = t
                  , sshKeyValue = v }
  toDocument k = [ (u "_id")   =: sshKeyId k
                 , (u "title") =: sshKeyTitle k
                 , (u "value") =: sshKeyValue k ]
  collectionName = error "Not insertable"

-- | Generate the SSH fingerprint format for the 'SSHKey' based on
-- draft-ietf-secsh-fingerprint-00 (matches output from
-- ssh-keygen -lf [pubkey_file])
fingerprint :: SSHKey -> String
fingerprint key = separate . show $ md5 keyData
  where keyData = lazyfy $ B64.decodeLenient key64
        key64 = case S8.words keyVal of
                  (_:blob:_) -> blob
                  [blob]     -> blob
                  _          -> S8.empty
        keyVal = case sshKeyValue key of
                   (Binary bs) -> bs
        separate (a:b:c:xs) = a:b:':':separate (c:xs)
        separate a = a
        lazyfy = L8.pack . S8.unpack
