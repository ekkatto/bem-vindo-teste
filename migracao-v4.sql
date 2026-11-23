-- Migração v4:
--  * o admin é avisado no momento do cadastro (não mais na confirmação de email)
--  * troca de senha (esqueci minha senha) fica pendente até o admin aprovar
-- Rode no SQL Editor do Supabase DEPOIS da migracao-v3.sql.
-- Também: desligue "Confirm email" em Authentication > Sign In / Providers > Email.

create extension if not exists pgcrypto with schema extensions;

-- 1) Aviso ao admin no cadastro: troca o gatilho da v3 (que esperava a confirmação)
drop trigger if exists on_email_confirmed on auth.users;
drop function if exists public.notify_admin_on_confirm();

create or replace function public.notify_admin_on_signup()
returns trigger
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  perform net.http_post(
    url := 'https://zohlwifvwocdcuajuvmb.supabase.co/functions/v1/notificar-admin',
    headers := jsonb_build_object('Content-Type', 'application/json'),
    body := jsonb_build_object('user_id', new.id)
  );
  return new;
end;
$$;

drop trigger if exists on_profile_created_notify on public.profiles;
create trigger on_profile_created_notify
  after insert on public.profiles
  for each row execute function public.notify_admin_on_signup();

-- 2) Troca de senha pendente
alter table public.profiles add column if not exists password_pending boolean not null default false;

-- Hash da senha nova. Nenhum cliente acessa essa tabela: só as funções abaixo.
create table if not exists public.password_changes (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  password_hash text not null,
  requested_at timestamptz not null default now()
);
alter table public.password_changes enable row level security;
revoke all on public.password_changes from anon, authenticated;

-- Usuário (com o link do email) define a nova senha: fica pendente
create or replace function public.request_password_change(p_password text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if auth.uid() is null then
    raise exception 'não autenticado';
  end if;
  if length(p_password) < 6 then
    raise exception 'a senha precisa ter pelo menos 6 caracteres';
  end if;
  insert into public.password_changes (user_id, password_hash)
  values (auth.uid(), extensions.crypt(p_password, extensions.gen_salt('bf')))
  on conflict (user_id) do update
    set password_hash = excluded.password_hash, requested_at = now();
  update public.profiles set password_pending = true where id = auth.uid();
end;
$$;

-- Admin aprova: aplica o hash na senha do Auth
create or replace function public.admin_approve_password(p_id uuid)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.is_admin() then
    raise exception 'acesso negado';
  end if;
  update auth.users u
     set encrypted_password = pc.password_hash, updated_at = now()
    from public.password_changes pc
   where pc.user_id = p_id and u.id = p_id;
  if not found then
    raise exception 'não há troca de senha pendente';
  end if;
  delete from public.password_changes where user_id = p_id;
  update public.profiles set password_pending = false where id = p_id;
end;
$$;

-- Admin recusa: descarta a senha nova (a antiga continua valendo)
create or replace function public.admin_reject_password(p_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'acesso negado';
  end if;
  delete from public.password_changes where user_id = p_id;
  update public.profiles set password_pending = false where id = p_id;
end;
$$;

revoke execute on function public.request_password_change(text) from public, anon;
revoke execute on function public.admin_approve_password(uuid) from public, anon;
revoke execute on function public.admin_reject_password(uuid) from public, anon;
grant execute on function public.request_password_change(text) to authenticated;
grant execute on function public.admin_approve_password(uuid) to authenticated;
grant execute on function public.admin_reject_password(uuid) to authenticated;
