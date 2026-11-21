-- Supabase — auth do dono da Página de Prospecção (PABLO WEB)
-- Como usar: no painel do Supabase, vai em SQL Editor > New query, cola
-- tudo e clica em Run. Este arquivo NÃO contém nenhuma senha, chave ou
-- código — só a estrutura da tabela. A senha do dono é criada por ele na
-- própria página (#/prospeccao → Admin → primeiro acesso, com o código de
-- setup que ele já recebeu) e guardada aqui só como hash PBKDF2.
--
-- Pré-requisito: as 7 tabelas de supabase-tabelas.sql já criadas.

create table if not exists public.owner_auth (
  id int primary key default 1,
  password_hash text,
  setup_code_hash text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.owner_auth enable row level security;
-- Sem políticas: só o backend (service_role key, no servidor da Vercel)
-- lê e escreve aqui. O navegador nunca acessa esta tabela direto.
