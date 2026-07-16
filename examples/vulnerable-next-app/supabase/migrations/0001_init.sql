-- Deliberately vulnerable fixture migration.
create table public.profiles (id uuid primary key, email text);
alter table public.profiles disable row level security;
create policy "open door" on public.profiles for all using (true);
