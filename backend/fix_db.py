import asyncio
import asyncpg

async def fix_db():
    connection_strings = [
        'postgresql://postgres:admin@localhost:5432/postgres',
        'postgresql://postgres:root@localhost:5432/postgres',
        'postgresql://postgres:1234@localhost:5432/postgres',
        'postgresql://postgres:123456@localhost:5432/postgres',
        'postgresql://root:root@localhost:5432/postgres',
        'postgresql://admin:admin@localhost:5432/postgres',
    ]

    conn = None
    success_uri_prefix = None
    for uri in connection_strings:
        try:
            print(f"Trying {uri}...")
            conn = await asyncpg.connect(uri)
            success_uri_prefix = uri.split('@')[0]
            print(f"Success with {success_uri_prefix}!")
            break
        except Exception:
            pass

    if not conn:
        print("Error: Could not connect to Postgres with any known credentials.")
        return

    try:
        # Check if 'svt' db exists
        db_exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname='svt'")
        if not db_exists:
            print("Creating database svt...")
            await conn.execute("CREATE DATABASE svt")
        
        # Check if 'svt_app' role exists
        role_exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname='svt_app'")
        if not role_exists:
            print("Creating role svt_app...")
            await conn.execute("CREATE ROLE svt_app WITH LOGIN PASSWORD 'local_app_db_123'")
        else:
            print("Updating role svt_app password...")
            await conn.execute("ALTER ROLE svt_app WITH PASSWORD 'local_app_db_123'")
            
        print("Granting database privileges...")
        await conn.execute("GRANT ALL PRIVILEGES ON DATABASE svt TO svt_app")
        await conn.close()

        print("Connecting to svt database to grant schema privileges...")
        conn2 = await asyncpg.connect(f'{success_uri_prefix}@localhost:5432/svt')
        
        # We need to grant usage to the public schema
        await conn2.execute("GRANT ALL ON SCHEMA public TO svt_app")
        await conn2.close()
        
        print("DB fix applied successfully!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(fix_db())
