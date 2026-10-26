{-# LANGUAGE RoleAnnotations #-}

module Memory.Memo.Pointer.Effect where

import Memory.Prelude

import Foreign.Storable as Foreign

{-
StatePtr but better, hypothetically
This collapses the state token into the effects list, but there might be
value found in keeping them separate, eg:

type role EffPtr nominal nominal representational
newtype EffPtr (st :: Type) (effs :: [Type]) a = MkEffPtr (Ptr a)

This is fine for now
-}

type role State nominal
data State s

type NoStateError s = TypeError ('Text "No state: " ':<>: 'ShowType s)

-- NOTE: Might flip order, make 'HasFoo ctx s'
type family HasState (s :: Type) (ctx :: [Type]) :: Constraint where
    HasState s (State s ': _ctx) = ()
    HasState s (_ ': ctx)        = HasState s ctx
    HasState s '[]               = NoStateError s

type role Perm nominal
data Perm p

type NoPermError s = TypeError ('Text "No permission: " ':<>: 'ShowType s)

-- NOTE: Might flip order, make 'HasFoo ctx s'
type family HasPerm (s :: Type) (ctx :: [Type]) :: Constraint where
    HasPerm s (Perm s ': _ctx) = ()
    HasPerm s (_ ': ctx)       = HasPerm s ctx
    HasPerm s '[]              = NoPermError s

data Readable
data Writeable

type role EffPtr nominal representational
newtype EffPtr (effs :: [Type]) a = MkEffPtr (Ptr a)

{- Eg:

type IOPtr a = EffPtr '[ State RealWorld, Perm Readable, Perm Writeable ] a

readEffPtr :: (HasPerm Readable ctx, Storable a) => EffPtr ctx a -> IO a
readEffPtr (MkEffPtr p) = Foreign.peek p

writeEffPtr :: (HasPerm Writeable ctx, Storable a) => EffPtr ctx a -> a -> IO ()
writeEffPtr (MkEffPtr p) = Foreign.poke p

-}
