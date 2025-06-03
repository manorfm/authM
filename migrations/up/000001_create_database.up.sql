-- CREATE DATABASE users;

-- Verifica se o banco de dados já existe antes de criar
DO
$$
BEGIN
   IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'users') THEN
      PERFORM dblink_exec('dbname=postgres', 'CREATE DATABASE users');
   END IF;
END;
$$;