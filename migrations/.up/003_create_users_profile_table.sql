DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type
        WHERE typname = 'gender_enum'
    ) THEN
        CREATE TYPE gender_enum AS ENUM ('male', 'female');
    END IF;
END
$$;

create table if not exists user_profiles (
    id bigserial primary key,
    user_id bigint not null unique references users(id) on delete cascade,
    full_name varchar(100) not null,
    avatar_url text null,
    gender gender_enum null,
    birth_date date null,
    address text null,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);