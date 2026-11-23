// Edge Function: envia email para os admins quando um novo usuário se cadastra.
// Secrets necessários (Project Settings > Edge Functions > Secrets):
//   RESEND_API_KEY  -> chave da API do Resend
//   EMAIL_FROM      -> (opcional) remetente, ex.: "Cadastros <onboarding@resend.dev>"
// SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY são fornecidos automaticamente.
// Publique com "Verify JWT" DESLIGADO, pois o gatilho do banco chama a função sem login.

import { createClient } from "npm:@supabase/supabase-js@2";

const escapar = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

Deno.serve(async (req) => {
  try {
    const { user_id } = await req.json();
    if (!user_id) return new Response("user_id obrigatório", { status: 400 });

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    // 1) Só notifica cadastros que ainda aguardam aprovação
    const { data: perfil } = await admin
      .from("profiles")
      .select("username, full_name, email, status")
      .eq("id", user_id)
      .single();
    if (!perfil || perfil.status !== "pending") {
      return new Response("ignorado: não está pendente", { status: 200 });
    }

    // 2) Destinatários: todos os admins
    const { data: admins } = await admin.from("profiles").select("email").eq("role", "admin");
    const destinos = (admins ?? []).map((a) => a.email).filter(Boolean);
    if (!destinos.length) return new Response("nenhum admin cadastrado", { status: 200 });

    // 3) Envia pelo Resend
    const html = `
      <p>Um novo usuário confirmou o email e aguarda sua aprovação:</p>
      <ul>
        <li><b>Usuário:</b> ${escapar(perfil.username)}</li>
        <li><b>Nome:</b> ${escapar(perfil.full_name)}</li>
        <li><b>Email:</b> ${escapar(perfil.email)}</li>
      </ul>
      <p>Aprove em: <a href="https://ekkatto.github.io/bem-vindo-teste/admin.html">painel do admin</a></p>`;

    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${Deno.env.get("RESEND_API_KEY")}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: Deno.env.get("EMAIL_FROM") ?? "onboarding@resend.dev",
        to: destinos,
        subject: `Aprovação pendente: ${perfil.username}`,
        html,
      }),
    });

    if (!res.ok) {
      const txt = await res.text();
      console.error("Resend erro:", res.status, txt);
      return new Response("erro ao enviar email", { status: 502 });
    }
    return new Response("email enviado", { status: 200 });
  } catch (err) {
    console.error(err);
    return new Response("erro interno", { status: 500 });
  }
});
