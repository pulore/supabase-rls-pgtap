# Testing Supabase RLS policies with pgTAP: a runnable example

The example behind Pulore's guide to testing Supabase RLS policies with pgTAP, locally and in CI. It's the database of Acme, a made-up client portal for small studios: a schema with deliberate row level security (RLS) holes, the migration that fixes them, and the pgTAP tests that tell the two apart. Every person and company in it is invented, and every address is on example.com.

The tests need only Postgres, so there's no app to build.

## What's in it

```
supabase/config.toml                              local stack settings, in the CLI v3 format
supabase/migrations/20260914…sql to 20261008…sql  the app's six migrations, holes included
supabase/migrations/20261106090000_…sql           the fix, one section per finding
supabase/seed.sql                                 two studios, seven users, 68 invoices, 44 messages
supabase/tests/database/access-rules.test.sql     40 tests of who can read and change what
supabase/tests/database/rls-techniques.test.sql   25 tests of the techniques the post explains
experiments/                                      the suite with one change each, run by hand
.github/workflows/db-tests.yml                    runs the tests on every push to main and every pull request
```

## Run it

You need Docker, and Node.js for npx (we used Node.js 26.12.1). Every command runs Supabase CLI 3.1.0 through npx, so nothing is installed globally. The first one asks before it downloads the package. Run them from this folder:

1. Start Postgres. This applies all seven migrations, the fix included, and the seed.

   ```sh
   npx supabase@3.1.0 db start
   ```

2. Rebuild the database without the last migration, the fix. This is the vulnerable schema.

   ```sh
   npx supabase@3.1.0 db reset --last 1
   ```

3. Run the tests. 38 of the suite's 40 tests and 7 of the techniques file's 25 fail, and the command exits with status 1.

   ```sh
   npx supabase@3.1.0 test db
   ```

4. Apply the fix.

   ```sh
   npx supabase@3.1.0 migration up
   ```

5. Run the tests again. All 65 pass, and the command exits with status 0.

   ```sh
   npx supabase@3.1.0 test db
   ```

6. Stop Postgres and delete its data.

   ```sh
   npx supabase@3.1.0 stop --no-backup
   ```

The two suite tests that pass in step 3 check that Sam can still change his name and still see Maya, his studio's owner. A schema that's too open passes those as well.

The config moves the local ports to 54520 to 54529, so the example can run beside a project on the default ports.

## How the tests work

- **One transaction per file.** Each file starts with `begin` and ends with `rollback`, so whatever the tests write is undone.
- **Acting as a user.** A test switches to the `anon` or `authenticated` role with `set local role` and sets the request's claims with `set local request.jwt.claims`, the way Supabase's API does. `supabase test db` connects as `postgres`, which bypasses RLS, so a test that forgets to switch sees every row.
- **An answer key.** Before any test switches role, the suite copies every invoice's ID, studio and client into `tests.invoice_key`. Tests then compare the IDs a user gets with the IDs they should get, using pgTAP's `set_eq`. A count of 20 can't tell Sam's 20 invoices from Priya's 20.
- **A regression case.** Tests 25 and 26 link Sam's login to Priya's client record for a moment, as a bad backfill might. He still counts 20 invoices, but the IDs show they're hers.
- **Files to refuse.** The suite adds three rows to `storage.objects` inside its transaction, so the storage tests have files to refuse. The insert names no conflict columns, because Storage's own unique indexes on that table change between versions.
- **Two helpers.** `tests.visible_rows` and `tests.changed_rows` count what a query sees or a statement changes, and turn an unexpected error into -1, so one test fails without stopping the run.

## The post's experiments

Each file in `experiments/` is the suite with one change. Run them while Postgres is up:

- After step 2, `npx supabase@3.1.0 test db experiments/no-storage-rows.test.sql` runs the suite without its `storage.objects` rows. 31 of 40 tests fail instead of 38, because seven storage tests pass against an empty bucket.
- After step 4, `npx supabase@3.1.0 test db experiments/deny-all.test.sql` drops every policy in `public` and `storage` inside its transaction, so RLS refuses everything. 28 of the 40 tests still pass.

## What the tests don't cover

They check the database's rules for the users and rows in the seed. They send no HTTP requests, so they don't check the API itself, Edge Functions, auth settings, or where your app keeps its keys.

## Checked on

12 November 2026, on macOS 27.0.1 (arm64) with Docker 29.9.2 and Node.js 26.12.1: Supabase CLI 3.1.0 through npx, Postgres 17.11 (image `supabase/postgres` 17.11.0.018), pgTAP 1.3.3, and the `pg_prove` 3.36 image that `supabase test db` starts. Every step above gave the results it describes, and so did both experiments. The workflow's two commands, `supabase db start` and `supabase test db`, passed in a fresh copy of this folder on the same Mac. Those runs added `--network-id`, for a Docker network of our own, and `--agent no`, which stops CLI 3.1.0 from switching some commands' output to JSON when a coding agent runs them.

## Who maintains this

[Pulore](https://pulore.com), a software studio in Dubai. If you'd like someone to check that your rules are the right ones, not only that your tests pass, see our [code audit](https://pulore.com/services/code-audit).

Issues and pull requests are welcome.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
