# The provisioned engine-tier container, baked so CI can CACHE it (issue #478).
#
# WHY THIS FILE EXISTS. test/engine-container.sh reaches the network three times
# before a single test runs — the image pull, `zypper refresh`, `zypper install`
# — and all three are measured ways the engine job dies printing no test name.
# Building them into an image once lets the workflow keep the result in the
# GitHub Actions cache and reach openSUSE at most weekly instead of several
# times a day.
#
# IT CALLS THE SCRIPT; IT DOES NOT REPEAT IT. The package list, the
# --no-recommends reasoning and every infra_fail classification live in
# engine-container.sh's install_packages and nowhere else. A dockerfile with its
# own `zypper install` line would be a second copy that drifts on the first
# package added, which is this project's most repeated defect.
#
# LOCAL USE NEEDS NOTHING FROM THIS FILE. `make integration-engine` still pulls
# the plain Tumbleweed image and provisions at run time; provision detects the
# tools are missing and installs them exactly as before. This file is an
# optimisation the workflow opts into by passing SNUG_ENGINE_IMAGE, not a new
# way the suite works.
ARG BASE_IMAGE=registry.opensuse.org/opensuse/tumbleweed:latest
FROM ${BASE_IMAGE}

# CACHE_EPOCH records the build date in the image so a log says how old the
# provisioning is. Expiry is not enforced here: the workflow caches the built
# image and rebuilds when the cached one is more than 7 days old.
ARG CACHE_EPOCH=unset
RUN echo "cache epoch: ${CACHE_EPOCH}"

COPY test/engine-container.sh /engine-container.sh

# SNUG_ENGINE_CONTAINER=1 is the same assertion provision makes: this changes the
# machine it runs on and refuses anywhere that is not a throwaway container.
RUN SNUG_ENGINE_CONTAINER=1 bash /engine-container.sh install-packages

# Deleted rather than left lying about: the copy above is a BUILD input, and a
# stale duplicate of the script inside the image is exactly the kind of second
# copy the header refuses. The container runs /src/test/engine-container.sh from
# the bind-mounted checkout, which is the version under test.
RUN rm -f /engine-container.sh
