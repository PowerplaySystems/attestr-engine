-- Add logo_url column for custom branding on PDF evidence exports
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_url TEXT;
