## .NET (NuGet)

### Modern SDK-style projects (.csproj / .fsproj)

```xml
-<PackageReference Include="Newtonsoft.Json" Version="11.0.1" />
+<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
```

If the version comes from `Directory.Packages.props` (central package
management), edit it there instead — the `PackageReference` in the project file
will have no `Version` attribute at all:

```xml
<PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
```

### Legacy packages.config

```xml
-<package id="Newtonsoft.Json" version="11.0.1" targetFramework="net472" />
+<package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" />
```

A `packages.config` project usually also has the version written into
`<HintPath>` elements inside the `.csproj`. Update those too, or the build will
still reference the old assembly path.

### Lockfile

Only present if the project opted in (`packages.lock.json`). Regenerate with:

```bash
dotnet restore --force-evaluate
```

If `dotnet` is unavailable, note it in `manual_steps`.

### If the package is transitive

Add a direct `PackageReference` at the fixed version. NuGet's nearest-wins
resolution means a direct reference overrides the transitive one. Say in
`diff_summary` that you added a reference rather than bumping an existing one.

### Watch for

A new target-framework floor (`net6.0` and later drops older TFMs). Flag it in
`manual_steps` rather than editing `<TargetFramework>` yourself.
