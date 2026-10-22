create extension if not exists pgcrypto;

create table if not exists public.user_profiles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 display_name text,
 is_admin boolean not null default false,
 can_view boolean not null default false,
 can_add boolean not null default false,
 can_edit boolean not null default false,
 can_delete boolean not null default false,
 active boolean not null default true,
 created_at timestamptz not null default now()
);
create table if not exists public.customers (
 id uuid primary key default gen_random_uuid(),
 first_name text not null check(length(trim(first_name)) between 1 and 100),
 last_name text not null check(length(trim(last_name)) between 1 and 100),
 phone text, notes text,
 assigned_to uuid references auth.users(id) on delete set null,
 created_by uuid not null default auth.uid() references auth.users(id),
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create unique index if not exists customers_unique_name on public.customers(lower(trim(first_name)),lower(trim(last_name)));
create table if not exists public.documents (
 id uuid primary key default gen_random_uuid(),
 customer_id uuid not null references public.customers(id) on delete cascade,
 document_type text not null check(document_type in ('บัตรประชาชน','ทะเบียนบ้าน','หนังสือเดินทาง','เอกสารอื่น ๆ')),
 file_name text not null, storage_path text not null unique, ocr_text text,
 id_number text, date_of_birth date, expiry_date date, address text,
 created_by uuid not null default auth.uid() references auth.users(id),
 created_at timestamptz not null default now()
);
create table if not exists public.audit_logs (
 id bigint generated always as identity primary key,
 actor_id uuid not null default auth.uid() references auth.users(id),
 action text not null, table_name text not null, record_id text,
 details jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);

create or replace function public.is_active_user() returns boolean
language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.user_profiles where user_id=auth.uid() and active); $$;
create or replace function public.is_admin_user() returns boolean
language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.user_profiles where user_id=auth.uid() and active and is_admin); $$;
create or replace function public.has_permission(p text) returns boolean
language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.user_profiles where user_id=auth.uid() and active and
(is_admin or (p='view' and can_view) or (p='add' and can_add) or (p='edit' and can_edit) or (p='delete' and can_delete))); $$;
create or replace function public.can_access_customer(cid uuid) returns boolean
language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.customers c where c.id=cid and
(public.is_admin_user() or c.assigned_to=auth.uid() or c.created_by=auth.uid())); $$;

alter table public.user_profiles enable row level security;
alter table public.customers enable row level security;
alter table public.documents enable row level security;
alter table public.audit_logs enable row level security;

create policy "profile_self_or_admin_read" on public.user_profiles for select to authenticated
using(user_id=auth.uid() or public.is_admin_user());
create policy "profile_admin_update" on public.user_profiles for update to authenticated
using(public.is_admin_user()) with check(public.is_admin_user());
create policy "profile_admin_insert" on public.user_profiles for insert to authenticated
with check(public.is_admin_user());
create policy "profile_admin_delete" on public.user_profiles for delete to authenticated
using(public.is_admin_user());

create or replace function public.new_user_profile() returns trigger
language plpgsql security definer set search_path=''
as $$ begin
 insert into public.user_profiles(user_id,display_name,is_admin,can_view,can_add,can_edit,can_delete,active)
 values(new.id,coalesce(new.raw_user_meta_data->>'display_name',''),false,false,false,false,false,true)
 on conflict(user_id) do nothing;
 return new;
end; $$;
drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile after insert on auth.users
for each row execute procedure public.new_user_profile();

create policy "customers_read_scoped" on public.customers for select to authenticated
using(public.is_active_user() and public.has_permission('view') and
(public.is_admin_user() or assigned_to=auth.uid() or created_by=auth.uid()));
create policy "customers_insert_perm" on public.customers for insert to authenticated
with check(public.is_active_user() and public.has_permission('add') and
(public.is_admin_user() or assigned_to is null or assigned_to=auth.uid()));
create policy "customers_update_scoped" on public.customers for update to authenticated
using(public.is_active_user() and public.has_permission('edit') and
(public.is_admin_user() or assigned_to=auth.uid() or created_by=auth.uid()))
with check(public.is_active_user() and public.has_permission('edit') and
(public.is_admin_user() or assigned_to=auth.uid() or created_by=auth.uid()));
create policy "customers_delete_scoped" on public.customers for delete to authenticated
using(public.is_active_user() and public.has_permission('delete') and
(public.is_admin_user() or assigned_to=auth.uid() or created_by=auth.uid()));

create policy "documents_read_scoped" on public.documents for select to authenticated
using(public.is_active_user() and public.has_permission('view') and public.can_access_customer(customer_id));
create policy "documents_insert_scoped" on public.documents for insert to authenticated
with check(public.is_active_user() and public.has_permission('add') and public.can_access_customer(customer_id));
create policy "documents_update_scoped" on public.documents for update to authenticated
using(public.is_active_user() and public.has_permission('edit') and public.can_access_customer(customer_id))
with check(public.is_active_user() and public.has_permission('edit') and public.can_access_customer(customer_id));
create policy "documents_delete_scoped" on public.documents for delete to authenticated
using(public.is_active_user() and public.has_permission('delete') and public.can_access_customer(customer_id));

create policy "audit_admin_or_actor_read" on public.audit_logs for select to authenticated
using(public.is_admin_user() or actor_id=auth.uid());

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('customer-documents','customer-documents',false,15728640,array['image/jpeg','image/png','image/webp','application/pdf'])
on conflict(id) do update set public=false,file_size_limit=15728640,allowed_mime_types=array['image/jpeg','image/png','image/webp','application/pdf'];
create policy "storage_read_own_uploads" on storage.objects for select to authenticated
using(bucket_id='customer-documents' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "storage_upload_own_folder" on storage.objects for insert to authenticated
with check(bucket_id='customer-documents' and (storage.foldername(name))[1]=auth.uid()::text and public.is_active_user() and public.has_permission('add'));
create policy "storage_delete_own_uploads" on storage.objects for delete to authenticated
using(bucket_id='customer-documents' and (storage.foldername(name))[1]=auth.uid()::text and public.is_active_user() and public.has_permission('delete'));

-- หลังสมัครบัญชีผู้ดูแลคนแรก ให้แทน UUID ของตนเองแล้วรัน:
-- update public.user_profiles set is_admin=true,can_view=true,can_add=true,can_edit=true,can_delete=true,active=true where user_id='YOUR-USER-UUID';
-- ห้ามใส่ service_role key ในโค้ดเว็บ
