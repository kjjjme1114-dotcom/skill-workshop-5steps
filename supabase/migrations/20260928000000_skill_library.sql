create table if not exists public.skills (
  id uuid primary key default gen_random_uuid(),
  slug text not null check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' and char_length(slug) <= 80),
  author_name text not null check (char_length(btrim(author_name)) between 1 and 50),
  title text not null check (char_length(btrim(title)) between 1 and 120),
  description text not null check (char_length(btrim(description)) between 1 and 500),
  skill_md text not null check (octet_length(skill_md) between 1 and 30000),
  created_at timestamptz not null default now()
);

create unique index if not exists skills_author_slug_unique
  on public.skills (lower(author_name), slug);
create index if not exists skills_created_at_desc
  on public.skills (created_at desc);

alter table public.skills enable row level security;
revoke all on public.skills from public, anon, authenticated;
grant select on public.skills to anon, authenticated;
grant select, insert on public.skills to service_role;
drop policy if exists "Anyone can read shared skills" on public.skills;
create policy "Anyone can read shared skills"
  on public.skills for select
  to anon, authenticated
  using (true);

create table if not exists public.skill_publish_limits (
  ip_hash text primary key check (ip_hash ~ '^[0-9a-f]{64}$'),
  window_started_at timestamptz not null,
  submission_count integer not null check (submission_count > 0)
);
alter table public.skill_publish_limits enable row level security;
revoke all on public.skill_publish_limits from public, anon, authenticated;

create or replace function public.consume_skill_publish_limit(p_ip_hash text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_count integer;
begin
  if p_ip_hash is null or p_ip_hash !~ '^[0-9a-f]{64}$' then
    return false;
  end if;

  delete from public.skill_publish_limits
    where window_started_at < now() - interval '2 days';

  insert into public.skill_publish_limits (ip_hash, window_started_at, submission_count)
    values (p_ip_hash, now(), 1)
  on conflict (ip_hash) do update
    set window_started_at = case
          when public.skill_publish_limits.window_started_at <= now() - interval '1 hour' then now()
          else public.skill_publish_limits.window_started_at
        end,
        submission_count = case
          when public.skill_publish_limits.window_started_at <= now() - interval '1 hour' then 1
          else public.skill_publish_limits.submission_count + 1
        end
  returning submission_count into current_count;

  return current_count <= 5;
end;
$$;

revoke all on function public.consume_skill_publish_limit(text) from public, anon, authenticated;
grant execute on function public.consume_skill_publish_limit(text) to service_role;
