-- Zona de Poder: authenticated accounts and trainer-assigned routines.
-- Run this once in the Supabase SQL Editor before enabling membership in the HTML.

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null,
  full_name text not null default '',
  role text not null default 'student' check (role in ('student', 'trainer')),
  created_at timestamptz not null default now()
);

create table if not exists public.student_routines (
  student_id uuid primary key references public.profiles (id) on delete cascade,
  assigned_by uuid not null references public.profiles (id),
  days jsonb not null default '{}'::jsonb check (jsonb_typeof(days) = 'object'),
  updated_at timestamptz not null default now()
);

create or replace function public.is_trainer()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles
    where id = (select auth.uid()) and role = 'trainer'
  );
$$;

revoke all on function public.is_trainer() from public;
grant execute on function public.is_trainer() to authenticated;

create or replace function public.create_student_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    lower(new.email),
    coalesce(new.raw_user_meta_data ->> 'full_name', '')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

revoke all on function public.create_student_profile() from public, anon, authenticated;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
  after insert on auth.users
  for each row execute function public.create_student_profile();

alter table public.profiles enable row level security;
alter table public.student_routines enable row level security;

revoke all on public.profiles from anon, public;
revoke all on public.student_routines from anon, public;
revoke all on public.profiles from authenticated;
revoke all on public.student_routines from authenticated;

drop policy if exists "Users read own profile; trainers read all profiles" on public.profiles;
create policy "Users read own profile; trainers read all profiles"
  on public.profiles for select to authenticated
  using (id = (select auth.uid()) or (select public.is_trainer()));

drop policy if exists "Students and trainers read assigned routines" on public.student_routines;
create policy "Students and trainers read assigned routines"
  on public.student_routines for select to authenticated
  using (student_id = (select auth.uid()) or (select public.is_trainer()));

drop policy if exists "Trainers create assigned routines" on public.student_routines;
create policy "Trainers create assigned routines"
  on public.student_routines for insert to authenticated
  with check (
    (select public.is_trainer())
    and assigned_by = (select auth.uid())
    and exists (
      select 1 from public.profiles
      where id = student_id and role = 'student'
    )
  );

drop policy if exists "Trainers update assigned routines" on public.student_routines;
create policy "Trainers update assigned routines"
  on public.student_routines for update to authenticated
  using ((select public.is_trainer()))
  with check (
    (select public.is_trainer())
    and assigned_by = (select auth.uid())
    and exists (
      select 1 from public.profiles
      where id = student_id and role = 'student'
    )
  );

drop policy if exists "Trainers remove assigned routines" on public.student_routines;
create policy "Trainers remove assigned routines"
  on public.student_routines for delete to authenticated
  using ((select public.is_trainer()));

grant select on public.profiles to authenticated;
grant select, insert, update, delete on public.student_routines to authenticated;

-- After registering the trainer account through the app, promote only that
-- account from the SQL Editor. Replace the email before executing this line.
-- update public.profiles
-- set role = 'trainer'
-- where email = lower('trainer@example.com');
