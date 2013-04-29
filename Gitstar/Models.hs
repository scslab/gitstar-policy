{-# LANGUAGE OverloadedStrings #-}
module Gitstar.Models (
  -- * Projects model
    ProjectId, ProjectName, Project(..), Public(..), isPublic
  , projectRepository, projectObjId
  -- * App model
  , GitstarApp(..)
  -- * Users
  , UserName, Url, User(..), newUser
  -- * Keys
  , KeyId, SSHKey(..), fingerprint
  , sshKeyToBson, sshKeyFromDocument
  ) where

import           Prelude hiding (lookup)

import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as S8
import           Data.Maybe
import           Data.Text (Text)
import qualified Data.Text as T

import           Hails.Data.Hson
import           Hails.Database.Structured
import           Hails.Web
import           Data.Hex

--
-- Projects
--



-- | Project id is simply an object id
type ProjectId = Maybe ObjectId

-- | Project name is simply a stirng
type ProjectName = Text

-- | A data type describing a project
data Project = Project {
    projectId            :: ProjectId
    -- ^ Project id
  , projectName          :: ProjectName
    -- ^ Project name
  , projectOwner         :: UserName
    -- ^ Project owner
  , projectDescription   :: Text
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
projectRepository :: Project -> Text
projectRepository proj = T.concat [projectOwner proj, "/", projectName proj, ".git"]

-- | get Project id of an already inserted project. Error otherwise
projectObjId :: Project -> ObjectId
projectObjId = fromJust . projectId

instance DCRecord Project where
  recordCollection _ = "projects"
  fromDocument doc = do
    pName  <- lookup "name" doc
    pOwner <- lookup "owner" doc
    let pDesc  = fromMaybe "" $ lookup "description" doc
        pColls = fromMaybe [] $ lookup "collaborators" doc
        pRedrs = fromMaybe [] $ lookup "readers" doc
        pPub = case look "public" doc of
                Just v | v == toHsonValue True -> True
                       | v == toHsonValue ("1" :: String) -> True
                       | otherwise -> False
                Nothing -> False
        pApps = fromMaybe [] $ lookup "apps" doc

    return $ Project
      { projectId            = lookup "_id" doc
      , projectName          = pName 
      , projectOwner         = pOwner
      , projectDescription   = pDesc
      , projectCollaborators = pColls
      , projectReaders       = if pPub then
                                Left Public
                                else Right pRedrs
      , projectApps          = pApps
      , projectForkedFrom    = lookup "forked_from" doc
      }

  toDocument proj =
    (maybe [] (\i -> ["_id" -: i]) $ projectId proj)
    ++
    [ "name"          -: projectName proj
    , "owner"         -: projectOwner proj
    , "description"   -: projectDescription proj
    , "collaborators" -: projectCollaborators proj
    , "readers"       -: either (const []) id (projectReaders proj)
    , "public"        -: either (const True) (const False) (projectReaders proj)
    , "apps"          -: projectApps proj
    , "forked_from"   -: projectForkedFrom proj]

--instance DCLabeledRecord GitstarPolicy Project where


--
-- Apps
--

-- | A gitstar app.
data GitstarApp = GitstarApp {
    appId          :: Text
  -- ^ Unique name for the app (not displayed to user)
  , appName        :: Text
  -- ^ Descriptive name of app (used to search for apps)
  , appTitle       :: Text
  -- ^ App title, to be displayed on project tabs
  , appUrl         :: Url
  -- ^ App url, containing @$user@ and @$project@ to be replaced by
  -- current user an app
  , appOwner       :: UserName
  -- ^ App owner
  , appDescription :: Text
  -- ^ App description
} deriving (Show)


instance DCRecord GitstarApp where
  recordCollection _ = "apps"
  fromDocument doc = do
    aId <- lookup "_id" doc
    aName <- lookup "name" doc
    aTitle <- lookup "title" doc
    aUrl  <- lookup "url" doc
    aOwner  <- lookup "owner" doc
    aDescription <- lookup "description" doc
    return $ GitstarApp
      { appId = aId
      , appName = aName
      , appTitle = aTitle
      , appUrl    = aUrl
      , appOwner = aOwner
      , appDescription = aDescription
      }

  toDocument app =
    [ "_id" -: (appId app)
    , "name" -: (appName app)
    , "title" -: (appTitle app)
    , "owner" -: (appOwner app)
    , "description" -: (appDescription app)
    , "url" -: (appUrl app)]

--
-- Users
--

-- | Email address of a user
type Email = Text

-- | URL
type Url = Text

-- | Data type describing users
data User = User { userName     :: UserName     -- ^ Username
                 , userKeys     :: [SSHKey]     -- ^ User's ssh keys
                 , userProjects :: [ProjectId]  -- ^ User's projects
                 , userFullName :: Maybe Text   -- ^ User's full name
                 , userCity     :: Maybe Text   -- ^ User's location
                 , userWebsite  :: Maybe Url    -- ^ User's website
                 , userGravatar :: Maybe Email  -- ^ User's gravatar e-mail
                 } deriving (Show, Eq)

newUser :: UserName -> User 
newUser uName = User { userName = uName
                     , userKeys = []
                     , userProjects = []
                     , userFullName = Nothing
                     , userCity = Nothing
                     , userWebsite = Nothing
                     , userGravatar = Nothing }

instance DCRecord User where
  recordCollection _ = "users"
  fromDocument doc = do
    uName   <- lookup "_id" doc
    keyDocs <- lookup "keys" doc
    keys <- mapM sshKeyFromDocument keyDocs
    (HsonValue (BsonArray uPrjs)) <- look "projects" doc
    let prjs = map (\(BsonObjId o) -> Just o) uPrjs
    return $ User { userName      = uName
                  , userKeys      = keys
                  , userProjects  = prjs
                  , userFullName = lookup "full_name" doc
                  , userCity = lookup "city" doc
                  , userWebsite = lookup "website" doc
                  , userGravatar = lookup "gravatar" doc}

  toDocument usr = [ "_id"       -: (userName usr)
                   , "keys"      -: (map sshKeyToBson $ userKeys usr)
                   , "projects"  -: (userProjects usr)
                   , "full_name" -: (userFullName usr)
                   , "city"      -: (userCity usr)
                   , "website"   -: (userWebsite usr)
                   , "gravatar"  -: (userGravatar usr)]

--instance DCLabeledRecord User where

--
-- Keys
--

-- | A key id is an object ID
type KeyId = ObjectId

-- | An SSH key has a name and key value
data SSHKey = SSHKey { sshKeyId    :: Maybe KeyId    -- ^ Key id
                     , sshKeyTitle :: !Text  -- ^ Name
                     , sshKeyValue :: !Binary  -- ^ Actual key
                     } deriving (Show, Eq)

sshKeyToBson :: SSHKey -> BsonDocument
sshKeyToBson k =
  [ BsonField "_id" (toBsonValue $ fmap BsonObjId $ sshKeyId k)
  , BsonField "title" (BsonString $ sshKeyTitle k)
  , BsonField "value" (BsonBlob $ sshKeyValue k)]


sshKeyFromDocument :: Monad m => BsonDocument -> m SSHKey
sshKeyFromDocument doc = do
  let kid = lookup "_id" doc
  title <- lookup "title" doc
  val <- lookup "value" doc
  return $
    SSHKey { sshKeyId = kid
           , sshKeyTitle = title
           , sshKeyValue = val }

-- | Generate the SSH fingerprint format for the 'SSHKey' based on
-- draft-ietf-secsh-fingerprint-00 (matches output from
-- ssh-keygen -lf [pubkey_file])
fingerprint :: SSHKey -> String
fingerprint key = separate . S8.unpack . hex $ MD5.hash keyData
  where keyData = B64.decodeLenient key64
        key64 = case S8.words keyVal of
                  (_:blob:_) -> blob
                  [blob]     -> blob
                  _          -> S8.empty
        keyVal = case sshKeyValue key of
                   (Binary bs) -> bs
        separate (a:b:c:xs) = a:b:':':separate (c:xs)
        separate a = a

