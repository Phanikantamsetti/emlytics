create table if not exists public.saved_reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  report_type text not null,
  target text not null,
  score integer,
  label text not null,
  summary jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists saved_reports_user_created_idx
  on public.saved_reports (user_id, created_at desc);

alter table public.saved_reports enable row level security;

drop policy if exists "Users manage their own saved reports" on public.saved_reports;
create policy "Users manage their own saved reports"
  on public.saved_reports for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create table if not exists public.watchlist (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  domain text not null,
  last_score integer,
  last_verdict text,
  last_checked_at timestamptz,
  created_at timestamptz not null default now(),
  unique (user_id, domain)
);

create index if not exists watchlist_user_created_idx
  on public.watchlist (user_id, created_at desc);

alter table public.watchlist enable row level security;

drop policy if exists "Users manage their own watchlist" on public.watchlist;
create policy "Users manage their own watchlist"
  on public.watchlist for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

revoke all on public.saved_reports, public.watchlist from anon;
grant select, insert, update, delete on public.saved_reports, public.watchlist to authenticated;
