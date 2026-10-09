# Additional permission under GNU GPL version 3 section 7

Warpshot is licensed under the GNU General Public License, version 3 or (at
your option) any later version (see `LICENSE`).

The Android app receives wake-up messages through Firebase Cloud Messaging,
whose client libraries depend on Google Play Services, which are not free
software. To allow distributing the app with those libraries, the copyright
holders grant the following additional permission:

> If you modify this Program, or any covered work, by linking or combining it
> with the Google Play Services client libraries or the Firebase client
> libraries (or a modified version of those libraries), containing parts
> covered by the terms of their respective licenses, the licensors of this
> Program grant you additional permission to convey the resulting work.
> Corresponding Source for a non-source form of such a combination shall not
> include the source code for the parts of those libraries used as well as
> that of the covered work.

This permission applies only to those libraries. Everything else stays under
the plain GPL. A push-provider–free build (UnifiedPush) is planned so that a
fully free variant can be distributed as well (see `docs/architecture.md`).
