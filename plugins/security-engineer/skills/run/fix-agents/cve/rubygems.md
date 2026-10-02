## Ruby (RubyGems)

### Gemfile

```ruby
-gem "rack", "2.2.3"
+gem "rack", "2.2.6.4"
```

If the gem is listed without a version, add an exact one:

```ruby
-gem "nokogiri"
+gem "nokogiri", "1.13.10"
```

### Regenerate the lockfile

```bash
bundle lock --update rack
```

`bundle lock` resolves without installing gems, and `--update <gem>` limits the
change to the one package. Avoid bare `bundle update`, which moves everything.

### If the gem is transitive

A gem that is in `Gemfile.lock` but not in `Gemfile` is a transitive dependency.
Add it to the `Gemfile` with an exact version to force resolution, then run
`bundle lock --update <gem>`. Say in `diff_summary` that you promoted a
transitive dependency to a direct one — a reviewer needs to know the Gemfile grew
an entry on purpose.

### If bundler is unavailable

Edit the `Gemfile` and note in `manual_steps` that `Gemfile.lock` needs
regenerating with `bundle lock --update <gem>`. Do not hand-edit `Gemfile.lock`;
its dependency graph section will not agree with itself.

### Watch for

A Rails-adjacent gem whose new version requires a newer Rails. Flag it rather
than starting a cascade of bumps.
