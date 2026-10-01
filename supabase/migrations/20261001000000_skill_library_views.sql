alter table public.skills
  add column if not exists view_count bigint not null default 0
  check (view_count >= 0);

create or replace function public.increment_skill_view_count(p_skill_id uuid)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  updated_view_count bigint;
begin
  if p_skill_id is null then
    raise exception 'skill_not_found';
  end if;

  update public.skills
    set view_count = view_count + 1
    where id = p_skill_id
    returning view_count into updated_view_count;

  if not found then
    raise exception 'skill_not_found';
  end if;

  return updated_view_count;
end;
$$;

revoke all on function public.increment_skill_view_count(uuid) from public, anon, authenticated;
grant execute on function public.increment_skill_view_count(uuid) to anon, authenticated;
