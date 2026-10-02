## Java (Maven)

The package name is a `groupId:artifactId` coordinate. Split it to find the
dependency block.

### pom.xml

```xml
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
-  <version>2.14.1</version>
+  <version>2.17.1</version>
</dependency>
```

If the version is a property, edit the property rather than the dependency block —
several artifacts usually share it, and they must move together:

```xml
<properties>
-  <log4j.version>2.14.1</log4j.version>
+  <log4j.version>2.17.1</log4j.version>
</properties>
```

### If the version is managed elsewhere

A dependency with no `<version>` is coming from a parent POM or a
`<dependencyManagement>` block, possibly a Spring Boot BOM. Pin it in this
project's own `<dependencyManagement>` rather than adding a bare `<version>` to
the dependency:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

Say in `diff_summary` that you overrode managed version resolution — it is a
different change from bumping a direct dependency.

### Gradle

`build.gradle` / `build.gradle.kts`: edit the version in the dependency string,
or the variable it references.

### There is no lockfile step

Maven resolves at build time. Do not run `mvn` — it downloads the world and is
slow. Put verification in `manual_steps`: "Run `mvn -q dependency:tree` to
confirm no conflicting managed version remains."

### Watch for

A transitive artifact still pulled in at the old version by another dependency.
`dependency:tree` is how a reviewer confirms it; flag that it needs checking.
