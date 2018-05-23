name := "java-jwt-wrapper"
version := "1.0"
description := "type-safe wrapper over java-jwt"
scalaVersion := "2.12.6"
scalacOptions := Seq(
  "-feature",
  "-deprecation",
  "-unchecked",
  "-Xlint:_",
  "-Ywarn-unused-import",
  "-Ywarn-unused:locals,privates",
  "-Ywarn-adapted-args",
  "-Ypartial-unification",
  "-encoding",
  "utf8",
  "-target:jvm-1.8",
  "-opt:l:inline",
  "-opt-inline-from:**"
)
logBuffered in Test := false

libraryDependencies ++= Seq(
  "com.auth0"          % "java-jwt"           % "3.3.0",
  "com.chuusai"        %% "shapeless"         % "2.3.3",
  "org.scalatest"      %% "scalatest"         % "3.0.4" % Test)
