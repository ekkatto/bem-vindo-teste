-- Rode este script no SQL Editor do Supabase (uma vez).

-- Tabela de perfis: um por usuário do Supabase Auth
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  full_name text not null,
  email text not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Permissões de acesso à tabela (sem isso a API responde "permission denied")
revoke all on public.profiles from anon;
grant select, update on public.profiles to authenticated;

-- Função que verifica se o usuário logado é admin (security definer evita recursão nas policies)
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.profiles where id = auth.uid() and role = 'admin'
  );
$$;

-- Usuário lê só o próprio perfil
create policy "usuario le proprio perfil"
  on public.profiles for select
  using (auth.uid() = id);

-- Admin lê todos os perfis e pode aprovar/rejeitar
create policy "admin le todos os perfis"
  on public.profiles for select
  using (public.is_admin());

create policy "admin atualiza perfis"
  on public.profiles for update
  using (public.is_admin())
  with check (public.is_admin());

-- Ao criar conta no Auth, cria o perfil automaticamente com status 'pending'
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, username, full_name, email)
  values (
    new.id,
    new.raw_user_meta_data->>'username',
    new.raw_user_meta_data->>'full_name',
    new.email
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- DEPOIS de criar sua própria conta pela página, rode isto trocando o email:
-- update public.profiles set role = 'admin', status = 'approved' where email = 'SEU_EMAIL_AQUI';
