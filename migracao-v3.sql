-- Migração v3: avisa o admin por email quando um usuário confirma o cadastro.
-- Rode no SQL Editor do Supabase DEPOIS da migracao-v2.sql.
-- Antes: publique a Edge Function "notificar-admin" (supabase/functions/notificar-admin/index.ts)
-- com "Verify JWT" desligado e configure o secret RESEND_API_KEY.

create extension if not exists pg_net with schema extensions;

-- Quando email_confirmed_at passa de nulo para preenchido, chama a Edge Function
create or replace function public.notify_admin_on_confirm()
returns trigger
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if old.email_confirmed_at is null and new.email_confirmed_at is not null then
    perform net.http_post(
      url := 'https://zohlwifvwocdcuajuvmb.supabase.co/functions/v1/notificar-admin',
      headers := jsonb_build_object('Content-Type', 'application/json'),
      body := jsonb_build_object('user_id', new.id)
    );
  end if;
  return new;
end;
$$;

drop trigger if exists on_email_confirmed on auth.users;
create trigger on_email_confirmed
  after update of email_confirmed_at on auth.users
  for each row execute function public.notify_admin_on_confirm();
