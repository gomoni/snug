# Introduction

This book is the user guide and a reference for configuring `snug`: where
configuration lives, the profile format, and what each key grants.

## The goals

The `snug` runs programs in a sandbox on Linux. The main goal of it is to protect a
host from the programs running inside the sandbox. Such program gets only the
files, environment, credentials and network configuration `snug` configuration
grants. It will often filter and reinterpret those before passing them to the
sandbox.

The second goal, which is just as important, is to provide an excellent and
simple user experience. Security tools tend to be hard to use and understand.
This one tries hard to be as simple as possible, which makes it opinionated.

 - the sandboxed environment should feel like a normal one as much as possible
 - tool avoid escape hatches like  `--priviledged` to weaken the sandbox
 - the only exception is `--no-seccomp`, which would disable ptrace or debuggers.
 - feature requests will be rejected if they contradict goal number one
 - tool itself should explain the sandbox as much as possible
 - and it should be easy to configure

## The profile model

A sandbox starts with nothing. An empty root filesystem, no network and with an
empty environment. This creates a secure, but not very usable sandbox.
Everything what must be available inside sandbox is granted by a profile. A
named set of grants.

Profiles are intended to be small, self-contained and can be combined together.
Following rules apply

 - A profile grants, there's nothing in a configuration to deny or exclude a
 thing. So in order to grant less, simply include less profiles.
 - Evaluation is order independent, so profiles `foo bar` and `bar foo` are the
   same set of grants.
 - When more profiles conflicts, this is a hard error.
 - An unknown key or value is an error
