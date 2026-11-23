-- Migração v2: bloqueio, pedido de desbloqueio, edição, exclusão e estatísticas.
-- Rode no SQL Editor do Supabase DEPOIS de ter rodado o schema.sql.

-- 1) Status: troca 'rejected' por 'blocked'
-- (derruba a constraint antiga antes, senão o update com 'blocked' falha)
alter table public.profiles drop constraint if exists profiles_status_check;
update public.profiles set status = 'blocked' where status = 'rejected';
alter table public.profiles add constraint profiles_status_check
  check (status in ('pending', 'approved', 'blocked'));

-- 2) Pedido de desbloqueio feito pelo próprio usuário bloqueado
alter table public.profiles add column if not exists unblock_requested boolean not null default false;

-- 3) Log de acessos (login e visitas), usado nas estatísticas
create table if not exists public.access_log (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  kind text not null check (kind in ('login', 'visit')),
  created_at timestamptz not null default now()
);

alter table public.access_log enable row level security;
revoke all on public.access_log from anon;
grant select on public.access_log to authenticated;

create policy "admin le log de acessos"
  on public.access_log for select
  using (public.is_admin());

-- 4) Funções

-- Registra login ou visita de um usuário aprovado
create or replace function public.register_access(p_kind text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_kind not in ('login', 'visit') then
    raise exception 'tipo de acesso inválido';
  end if;
  if not exists (select 1 from public.profiles where id = auth.uid() and status = 'approved') then
    raise exception 'acesso negado';
  end if;
  insert into public.access_log (user_id, kind) values (auth.uid(), p_kind);
end;
$$;

-- Usuário bloqueado pede desbloqueio
create or replace function public.request_unblock()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.profiles set unblock_requested = true
  where id = auth.uid() and status = 'blocked';
  if not found then
    raise exception 'a conta não está bloqueada';
  end if;
end;
$$;

-- Estatísticas por usuário (só admin recebe linhas)
create or replace function public.admin_user_stats()
returns table (user_id uuid, logins bigint, visits bigint, last_access timestamptz)
language sql
security definer
set search_path = public
stable
as $$
  select p.id,
         count(l.id) filter (where l.kind = 'login'),
         count(l.id) filter (where l.kind = 'visit'),
         max(l.created_at)
  from public.profiles p
  left join public.access_log l on l.user_id = p.id
  where public.is_admin()
  group by p.id;
$$;

-- Admin exclui a conta (apaga do Auth; o perfil e o log somem em cascata)
create or replace function public.admin_delete_user(p_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'acesso negado';
  end if;
  if p_id = auth.uid() then
    raise exception 'você não pode excluir a própria conta';
  end if;
  delete from auth.users where id = p_id;
end;
$$;

-- Permissões de execução: só usuários logados
revoke execute on function public.register_access(text) from public, anon;
revoke execute on function public.request_unblock() from public, anon;
revoke execute on function public.admin_user_stats() from public, anon;
revoke execute on function public.admin_delete_user(uuid) from public, anon;
grant execute on function public.register_access(text) to authenticated;
grant execute on function public.request_unblock() to authenticated;
grant execute on function public.admin_user_stats() to authenticated;
grant execute on function public.admin_delete_user(uuid) to authenticated;
