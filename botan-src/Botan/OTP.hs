module Botan.OTP where

import Botan.Internal.Prelude
import Botan.Hash
import Botan.Bindings.HOTP
import Botan.Bindings.TOTP

{-
Bindings Memorized instance
-}

instance Memorized BotanHOTP where
    type Memo BotanHOTP = Ptr
    type MemRep BotanHOTP = BotanHOTPStruct
    withMemo (MkBotanHOTP ptr) action = action ptr

{-
HOTP object
-}

newtype HOTP = MkHOTP { foreignPtr :: ForeignPtr BotanHOTPStruct }

instance Memorized HOTP where
    type Memo HOTP = ForeignPtr
    type MemRep HOTP = BotanHOTPStruct
    withMemo (MkHOTP fptr) action = action fptr

instance BotanObject HOTP where

    type BotanStruct HOTP = BotanHOTPStruct
    type BotanPtr    HOTP = BotanHOTP

    toBotanPtr :: Ptr (BotanStruct HOTP) -> BotanPtr HOTP
    toBotanPtr = MkBotanHOTP
    toBotan    = MkHOTP
    botanFinalizer  = botan_hotp_destroy

{-
HOTP data types
-}

type HOTPCode = Word32
type HOTPCounter = Word64
type HOTPKey = ByteString

{-
HOTP functions
-}

withHOTP :: HOTP -> (BotanHOTP -> IO a) -> IO a
withHOTP = withBotanPtr @HOTP

hotpInit
    :: HOTPType
    -> Int
    -> HOTPKey
    -> IO HOTP
hotpInit algo digits key = do
    useAsCString (hotpName algo) $ \ namePtr -> do
        withPtrLen key $ \ keyPtr keyLen -> do
            createBotan @HOTP $ \ outPtr -> botan_hotp_init
                outPtr
                (ConstPtr keyPtr)
                (fromIntegral keyLen)
                (ConstPtr namePtr)
                (fromIntegral digits)

hotpGenerate
    :: HOTP
    -> HOTPCounter
    -> IO HOTPCode
hotpGenerate hotp counter = withHOTP hotp $ \ hotpPtr -> do
    alloca $ \ codePtr -> do
        throwBotanIfNegative_ $ botan_hotp_generate hotpPtr codePtr counter
        peek codePtr

hotpCheck
    :: HOTP
    -> HOTPCode
    -> HOTPCounter
    -> Int
    -> IO (Bool, HOTPCounter)
hotpCheck hotp code counter resync =
    withHOTP hotp $ \ hotpPtr -> do
        mask_ $ alloca $ \ nextCounterPtr -> do
            valid <- throwBotanCatchingInvalidVerifier $ botan_hotp_check hotpPtr nextCounterPtr code counter (fromIntegral resync)
            nextCounter <- peek nextCounterPtr
            return (valid, nextCounter)

{-
HOTP algorithms
-}

data HOTPType
    = HOTP_SHA1
    | HOTP_SHA256
    | HOTP_SHA512
    deriving stock (Eq, Ord, Show)

hotpName :: HOTPType -> ByteString
hotpName HOTP_SHA1   = hashName SHA1
hotpName HOTP_SHA256 = hashName SHA256
hotpName HOTP_SHA512 = hashName SHA512

{-
Bindings Memorized instance
-}

instance Memorized BotanTOTP where
    type Memo BotanTOTP = Ptr
    type MemRep BotanTOTP = BotanTOTPStruct
    withMemo (MkBotanTOTP ptr) action = action ptr

{-
TOTP object
-}

newtype TOTP = MkTOTP { foreignPtr :: ForeignPtr BotanTOTPStruct }

instance Memorized TOTP where
    type Memo TOTP = ForeignPtr
    type MemRep TOTP = BotanTOTPStruct
    withMemo (MkTOTP fptr) action = action fptr

instance BotanObject TOTP where

    type BotanStruct TOTP = BotanTOTPStruct
    type BotanPtr    TOTP = BotanTOTP

    toBotanPtr = MkBotanTOTP
    toBotan    = MkTOTP
    botanFinalizer  = botan_totp_destroy


type TOTPDigits = Int -- Between 6 and 8
type TOTPKey = ByteString
type TOTPCode = Word32
type TOTPTimestep = Word64  -- How often the clock increments, eg 30s
type TOTPTimestamp = Word64 -- Unix epoch

withTOTP :: TOTP -> (BotanTOTP -> IO a) -> IO a
withTOTP = withBotanPtr @TOTP

totpInit
    :: TOTPType
    -> TOTPDigits
    -> TOTPTimestep
    -> TOTPKey
    -> IO TOTP
totpInit algo digits timestep key =
    useAsCString (totpName algo) $ \ namePtr ->
    withPtrLen key $ \ keyPtr keyLen ->
    createBotan @TOTP $ \ outPtr -> botan_totp_init
        outPtr
        (ConstPtr keyPtr)
        (fromIntegral keyLen)
        (ConstPtr namePtr)
        (fromIntegral digits)
        (fromIntegral timestep)

totpGenerate
    :: TOTP
    -> TOTPTimestamp
    -> IO TOTPCode
totpGenerate totp timestamp = withTOTP totp $ \ totpPtr ->
    alloca $ \ codePtr -> do
        throwBotanIfNegative_ $ botan_totp_generate totpPtr codePtr timestamp
        peek codePtr

totpCheck
    :: TOTP
    -> TOTPCode
    -> TOTPTimestamp
    -> Int              -- ^ acceptable clock drift, in time steps
    -> IO Bool
totpCheck totp code timestamp drift = mask_ $ withTOTP totp $ \ totpPtr ->
    throwBotanCatchingInvalidVerifier $
        botan_totp_check totpPtr code timestamp (fromIntegral drift)

{-
TOTP algorithms
-}

data TOTPType
    = TOTP_SHA1
    | TOTP_SHA256
    | TOTP_SHA512
    deriving stock (Eq, Ord, Show, Enum, Bounded)

totpName :: TOTPType -> ByteString
totpName TOTP_SHA1   = hashName SHA1
totpName TOTP_SHA256 = hashName SHA256
totpName TOTP_SHA512 = hashName SHA512

-- totpTypes :: [TOTPType]
-- totpTypes = [minBound .. maxBound]

-- Convenience function
-- NOTE: Probably need to re-order parameters for ergonomics, eg
-- - gen should be type / config, check should be type / config / output / variance
-- but usually TOTPCode comes too early
-- its because we're matching bindings exactly still here as a default for now

generateHOTPCode
    :: HOTPType
    -> Int          -- ^ digits, between 6 and 8
    -> HOTPKey
    -> HOTPCounter
    -> IO HOTPCode
generateHOTPCode algo digits key counter = do
    hotp <- hotpInit algo digits key
    hotpGenerate hotp counter

-- | One-shot HOTP code check. Returns @(is_valid, next_counter_to_use)@.
checkHOTPCode
    :: HOTPType
    -> Int          -- ^ digits, between 6 and 8
    -> HOTPKey
    -> HOTPCode
    -> HOTPCounter
    -> Int          -- ^ resync range
    -> IO (Bool, HOTPCounter)
checkHOTPCode algo digits key code counter resync = do
    hotp <- hotpInit algo digits key
    hotpCheck hotp code counter resync

generateTOTPCode
    :: TOTPType
    -> TOTPDigits
    -> TOTPTimestep
    -> TOTPKey
    -> TOTPTimestamp
    -> IO TOTPCode
generateTOTPCode algo digits timestep key timestamp = do
    totp <- totpInit algo digits timestep key
    totpGenerate totp timestamp

checkTOTPCode
    :: TOTPType
    -> TOTPDigits
    -> TOTPTimestep
    -> TOTPKey
    -> TOTPCode
    -> TOTPTimestamp
    -> Int          -- ^ acceptable clock drift, in time steps
    -> IO Bool
checkTOTPCode algo digits timestep key code timestamp drift = do
    totp <- totpInit algo digits timestep key
    totpCheck totp code timestamp drift
