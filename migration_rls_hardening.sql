-- ============================================================
-- RLSポリシーの是正(冪等版・何度実行しても安全)
--
-- 現状の問題:
--   links / programs / records に「roles=public, qual=true, with_check=true」
--   という無制限アクセスを許可するポリシー(ALL ACCESS 等)が存在し、
--   ログインすらしていない匿名ユーザーでも anon key だけで
--   全大会のプログラム・受信点・データを読み書き・削除できてしまう状態。
--   アプリのUI側にあるadmin/staffの権限分岐は、DB側では一切保証されていない。
--
-- 方針:
--   - すべてのアクセスをログイン済みユーザー(authenticated)限定にする
--   - 破壊的/管理系操作(番組・受信点の作成/削除、レコード削除、権限管理)は
--     is_admin() ヘルパー関数で判定し、管理者(admin@fpu.system、または
--     user_roles.role = 'admin' に昇格したユーザー)のみに許可する
--   - データ入力(records の SELECT/INSERT/UPDATE)は現場スタッフも必要なので
--     authenticated 全員に許可する
--
-- 適用手順:
--   1. Supabase SQL Editor でこのファイルを実行する(再実行しても安全)
--   2. アプリにadmin・staff両方のアカウントでログインし直し、以下を確認:
--      - staffで: ダッシュボード閲覧、データ入力、送信ができる
--      - staffで: メンテナンス画面(受信点追加/削除/CSV/番組作成削除)に
--        アクセスできない(UIにも出ないはずだが、念のためURL直打ち等でも確認)
--      - adminで: 上記すべての管理操作ができる
--   3. できればログアウト状態(またはシークレットウィンドウ)で
--      ブラウザの開発者ツールから直接 fetch/Supabase呼び出しを試し、
--      401/403相当のエラーになることを確認する
--
-- 対象外(このマイグレーションでは触っていません):
--   - memos テーブル: このアプリのコードからは参照されていないが、
--     他アプリで使われている可能性があるとのことなので今回はそのまま。
--     引き続き「誰でも読み書き可能」な状態なので、内容を確認して
--     早めに要否とアクセス制御を判断してください。
-- ============================================================

-- 0. 管理者判定ヘルパー関数
--    SECURITY DEFINER + search_path固定にして、user_roles自体のRLSを
--    参照する際に無限再帰(自分自身のポリシー評価でまた自分を呼ぶ)が
--    起きないようにしている
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select
    (auth.jwt() ->> 'email') = 'admin@fpu.system'
    or exists (
      select 1 from public.user_roles
      where id = auth.uid() and role = 'admin'
    );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

-- 1. links: 閲覧はログイン済み全員、作成/変更/削除は管理者のみ
drop policy if exists "ALL ACCESS" on public.links;

drop policy if exists "links_select_authenticated" on public.links;
create policy "links_select_authenticated" on public.links
  for select to authenticated using (true);

drop policy if exists "links_admin_write" on public.links;
create policy "links_admin_write" on public.links
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- 2. programs: 閲覧はログイン済み全員(既存ポリシーを流用)、
--    作成/変更/削除は管理者のみ
drop policy if exists "ALL ACCESS" on public.programs;
drop policy if exists "Allow all for admin" on public.programs;
-- "Allow select for authenticated users" は正しく機能しているのでそのまま残す

drop policy if exists "programs_admin_write" on public.programs;
create policy "programs_admin_write" on public.programs
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- 3. records: 閲覧・入力(SELECT/INSERT/UPDATE)はログイン済み全員、
--    削除は管理者のみ(現場UIに個別削除機能はなく、番組ごと削除は
--    admin操作の deleteProgramEntirely のみが対象)
drop policy if exists "ALL ACCESS" on public.records;
drop policy if exists "Allow insert/update/delete for everyone" on public.records;
drop policy if exists "Allow select and upsert for authenticated users" on public.records;
drop policy if exists "Allow select for everyone" on public.records;

drop policy if exists "records_select_authenticated" on public.records;
create policy "records_select_authenticated" on public.records
  for select to authenticated using (true);

drop policy if exists "records_insert_authenticated" on public.records;
create policy "records_insert_authenticated" on public.records
  for insert to authenticated with check (true);

drop policy if exists "records_update_authenticated" on public.records;
create policy "records_update_authenticated" on public.records
  for update to authenticated using (true) with check (true);

drop policy if exists "records_delete_admin" on public.records;
create policy "records_delete_admin" on public.records
  for delete to authenticated using (public.is_admin());

-- 4. user_roles: 昇格した admin ロールのユーザーも他ユーザーの権限を
--    管理できるようにする(従来は admin@fpu.system のみに限定されていた)
drop policy if exists "Allow all management for admin" on public.user_roles;
drop policy if exists "Allow read for users" on public.user_roles;

drop policy if exists "user_roles_admin_all" on public.user_roles;
create policy "user_roles_admin_all" on public.user_roles
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "user_roles_self_read" on public.user_roles;
create policy "user_roles_self_read" on public.user_roles
  for select to authenticated using (public.is_admin() or auth.uid() = id);

-- ============================================================
-- 5. 適用結果の確認
-- ============================================================
select tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public' and tablename in ('links','programs','records','user_roles')
order by tablename, policyname;
