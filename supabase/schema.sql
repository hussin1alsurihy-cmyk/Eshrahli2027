-- Eshrahli LMS database foundation
-- Run this file in Supabase SQL Editor after connecting the project.
-- Safe defaults: new users are students; users cannot grant themselves elevated roles.

create extension if not exists pgcrypto;

create type public.user_role as enum ('student', 'teacher', 'admin');
create type public.course_status as enum ('draft', 'published', 'archived');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  role public.user_role not null default 'student',
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.courses (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  slug text not null unique,
  description text not null default '',
  category text not null default 'عام',
  level text not null default 'تأسيسي',
  cover_url text,
  status public.course_status not null default 'draft',
  teacher_id uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.lessons (
  id uuid primary key default gen_random_uuid(),
  course_id uuid not null references public.courses(id) on delete cascade,
  title text not null,
  summary text not null default '',
  content jsonb not null default '{}'::jsonb,
  video_url text,
  resource_url text,
  sort_order integer not null default 0,
  is_published boolean not null default false,
  created_at timestamptz not null default now(),
  unique(course_id, sort_order)
);

create table public.enrollments (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  course_id uuid not null references public.courses(id) on delete cascade,
  enrolled_at timestamptz not null default now(),
  unique(student_id, course_id)
);

create table public.lesson_progress (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  lesson_id uuid not null references public.lessons(id) on delete cascade,
  completed boolean not null default false,
  completed_at timestamptz,
  updated_at timestamptz not null default now(),
  unique(student_id, lesson_id)
);

create table public.lesson_notes (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  lesson_id uuid not null references public.lessons(id) on delete cascade,
  body text not null default '',
  updated_at timestamptz not null default now(),
  unique(student_id, lesson_id)
);

create table public.quizzes (
  id uuid primary key default gen_random_uuid(),
  course_id uuid not null references public.courses(id) on delete cascade,
  lesson_id uuid references public.lessons(id) on delete cascade,
  title text not null,
  questions jsonb not null default '[]'::jsonb,
  is_published boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.quiz_attempts (
  id uuid primary key default gen_random_uuid(),
  quiz_id uuid not null references public.quizzes(id) on delete cascade,
  student_id uuid not null references public.profiles(id) on delete cascade,
  answers jsonb not null default '{}'::jsonb,
  score numeric(5,2),
  submitted_at timestamptz not null default now()
);

create index courses_status_idx on public.courses(status);
create index lessons_course_sort_idx on public.lessons(course_id, sort_order);
create index enrollments_student_idx on public.enrollments(student_id);
create index lesson_progress_student_idx on public.lesson_progress(student_id);
create index quiz_attempts_student_idx on public.quiz_attempts(student_id);

-- Automatically create a student profile when an auth account is registered.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'display_name', split_part(new.email, '@', 1), '')
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Keep updated_at current.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger profiles_updated_at before update on public.profiles
for each row execute function public.set_updated_at();
create trigger courses_updated_at before update on public.courses
for each row execute function public.set_updated_at();
create trigger progress_updated_at before update on public.lesson_progress
for each row execute function public.set_updated_at();
create trigger notes_updated_at before update on public.lesson_notes
for each row execute function public.set_updated_at();

-- Role helpers. The role is only elevated manually by a trusted administrator.
create or replace function public.current_user_role()
returns public.user_role
language sql
stable
security definer
set search_path = ''
as $$
  select role from public.profiles where id = (select auth.uid());
$$;

alter table public.profiles enable row level security;
alter table public.courses enable row level security;
alter table public.lessons enable row level security;
alter table public.enrollments enable row level security;
alter table public.lesson_progress enable row level security;
alter table public.lesson_notes enable row level security;
alter table public.quizzes enable row level security;
alter table public.quiz_attempts enable row level security;

-- Profile visibility and safe self-service fields.
create policy "Users can read own profile" on public.profiles
for select to authenticated using (id = (select auth.uid()) or public.current_user_role() = 'admin');
create policy "Admins can manage profiles" on public.profiles
for all to authenticated using (public.current_user_role() = 'admin')
with check (public.current_user_role() = 'admin');

revoke update on public.profiles from authenticated;
grant update (display_name, avatar_url) on public.profiles to authenticated;

-- Published catalog is readable; teachers manage their own courses; admins manage all.
create policy "Published courses are readable" on public.courses
for select to anon, authenticated using (status = 'published' or teacher_id = (select auth.uid()) or public.current_user_role() = 'admin');
create policy "Teachers manage own courses" on public.courses
for all to authenticated
using ((teacher_id = (select auth.uid()) and public.current_user_role() = 'teacher') or public.current_user_role() = 'admin')
with check ((teacher_id = (select auth.uid()) and public.current_user_role() = 'teacher') or public.current_user_role() = 'admin');

create policy "Published lessons are readable" on public.lessons
for select to anon, authenticated using (
  is_published and exists (select 1 from public.courses c where c.id = course_id and c.status = 'published')
  or exists (select 1 from public.courses c where c.id = course_id and c.teacher_id = (select auth.uid()))
  or public.current_user_role() = 'admin'
);
create policy "Course teachers manage lessons" on public.lessons
for all to authenticated
using (exists (select 1 from public.courses c where c.id = course_id and c.teacher_id = (select auth.uid()) and public.current_user_role() = 'teacher') or public.current_user_role() = 'admin')
with check (exists (select 1 from public.courses c where c.id = course_id and c.teacher_id = (select auth.uid()) and public.current_user_role() = 'teacher') or public.current_user_role() = 'admin');

-- Students can manage only their own enrollments, progress, notes and attempts.
create policy "Users read own enrollments" on public.enrollments
for select to authenticated using (student_id = (select auth.uid()) or public.current_user_role() = 'admin');
create policy "Students enroll themselves" on public.enrollments
for insert to authenticated with check (student_id = (select auth.uid()) and public.current_user_role() = 'student');
create policy "Admins manage enrollments" on public.enrollments
for all to authenticated using (public.current_user_role() = 'admin') with check (public.current_user_role() = 'admin');

create policy "Users manage own progress" on public.lesson_progress
for all to authenticated using (student_id = (select auth.uid()) or public.current_user_role() = 'admin')
with check (student_id = (select auth.uid()) or public.current_user_role() = 'admin');
create policy "Users manage own notes" on public.lesson_notes
for all to authenticated using (student_id = (select auth.uid()) or public.current_user_role() = 'admin')
with check (student_id = (select auth.uid()) or public.current_user_role() = 'admin');

create policy "Published quizzes readable" on public.quizzes
for select to authenticated using (is_published or public.current_user_role() = 'admin' or exists (
  select 1 from public.courses c where c.id = course_id and c.teacher_id = (select auth.uid())
));
create policy "Teachers manage quizzes" on public.quizzes
for all to authenticated
using (public.current_user_role() = 'admin' or exists (
  select 1 from public.courses c where c.id = course_id and c.teacher_id = (select auth.uid()) and public.current_user_role() = 'teacher'
))
with check (public.current_user_role() = 'admin' or exists (
  select 1 from public.courses c where c.id = course_id and c.teacher_id = (select auth.uid()) and public.current_user_role() = 'teacher'
));

create policy "Users read own quiz attempts" on public.quiz_attempts
for select to authenticated using (student_id = (select auth.uid()) or public.current_user_role() = 'admin');
create policy "Students submit own attempts" on public.quiz_attempts
for insert to authenticated with check (student_id = (select auth.uid()) and public.current_user_role() = 'student');

-- Important: promote the first platform administrator manually in the Supabase SQL editor:
-- update public.profiles set role = 'admin' where id = '<AUTH_USER_UUID>';
