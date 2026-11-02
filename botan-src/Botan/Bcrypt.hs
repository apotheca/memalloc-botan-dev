module Botan.Bcrypt
(   BcryptPassword
,   BcryptDigest
,   bcryptGenerate
,   bcryptIsValid
,   BcryptWorkFactor(..)
,   bcryptWorkFactor
,   bcrypt
,   bcryptAuth
) where

import Botan.Internal.Prelude
import Botan.Bindings.Bcrypt
import Botan.RNG

import qualified Data.ByteString as ByteString

{-
Bcrypt data types
-}

-- | A bcrypt password. Only the first 72 bytes are significant, and the
-- password is truncated at the first NUL byte.
type BcryptPassword = ByteString

-- | A bcrypt-hashed password digest, formatted as @$2a$...@.
type BcryptDigest = ByteString

-- | A work factor to slow down guessing attacks.
data BcryptWorkFactor
    = BcryptFast        -- ^ Should not cause noticable CPU usage
    | BcryptGood        -- ^ May cause noticable CPU usage
    | BcryptStrong      -- ^ May block for several seconds
    | BcryptCustom Int  -- ^ A custom work factor. 12 or greater is recommended.
    deriving stock (Eq, Ord, Show)

bcryptWorkFactor :: BcryptWorkFactor -> Int
bcryptWorkFactor BcryptFast       = BOTAN_BCRYPT_WORK_FACTOR_FAST
bcryptWorkFactor BcryptGood       = BOTAN_BCRYPT_WORK_FACTOR_GOOD
bcryptWorkFactor BcryptStrong     = BOTAN_BCRYPT_WORK_FACTOR_STRONG
bcryptWorkFactor (BcryptCustom n) = n

{-
Bcrypt functions
-}

-- NOTE: A bcrypt digest is 60 characters plus a NUL terminator. The documented
-- max password size is 72, but the output buffer is sized with some slack.
bcryptBufferSize :: Int
bcryptBufferSize = 80

-- | Create a password hash using bcrypt, with the provided RNG for the salt.
bcryptGenerate
    :: RNG
    -> BcryptWorkFactor
    -> BcryptPassword
    -> IO BcryptDigest
bcryptGenerate rng factor password =
    useAsCString password $ \ passwordPtr ->
    withRNG rng $ \ botanRNG ->
    mask_ $ alloca $ \ szPtr -> do
        poke szPtr (fromIntegral bcryptBufferSize)
        out <- allocInit ByteStringAllocator bcryptBufferSize $ \ fPtr ->
            withPtr fPtr $ \ outPtr ->
                throwBotanIfNegative_ $ botan_bcrypt_generate
                    outPtr
                    szPtr
                    (ConstPtr passwordPtr)
                    botanRNG
                    (fromIntegral (bcryptWorkFactor factor))
                    0   -- flags must be 0 in the current API revision
        return $!! ByteString.takeWhile (/= 0) out

{- |
Check a previously created password hash.

Returns 'True' iff the password / digest combination is valid, 'False' if it is
not valid (but otherwise well formed), and throws an exception on error.
-}
bcryptIsValid
    :: BcryptPassword
    -> BcryptDigest
    -> IO Bool
bcryptIsValid password digest =
    useAsCString password $ \ passwordPtr ->
    useAsCString digest $ \ digestPtr ->
    throwBotanCatchingInvalidVerifier $
        botan_bcrypt_is_valid (ConstPtr passwordPtr) (ConstPtr digestPtr)

{-
Convenience functions
-}

-- | One-shot bcrypt digest generation using the user threadsafe RNG.
bcrypt :: BcryptWorkFactor -> BcryptPassword -> IO BcryptDigest
bcrypt = bcryptGenerate userThreadsafeRNG

-- | One-shot password authentication against a stored digest.
bcryptAuth :: BcryptPassword -> BcryptDigest -> IO Bool
bcryptAuth = bcryptIsValid
