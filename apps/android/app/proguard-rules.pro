# JNA (used by the UniFFI bindings) finds classes, fields and callback
# methods by reflection and by name from native code.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-dontwarn java.awt.**
-dontwarn com.sun.jna.**

# UniFFI bindings: JNA structures, callback interfaces and the native method
# names must stay as generated.
-keep class uniffi.** { *; }

# The core's JNI entry point (Core.initAndroid) is looked up by name.
-keepclasseswithmembernames class io.github.guidin9.warpshot.Core {
    native <methods>;
}

# Firebase and ML Kit create their components by reflection; R8's full mode
# drops no-argument constructors unless kept (seen: FCM and the QR scanner's
# registrars failed with NoSuchMethodException).
-keep class * implements com.google.firebase.components.ComponentRegistrar { public <init>(); }
