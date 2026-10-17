CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  photo_url TEXT DEFAULT '',
  verified INTEGER DEFAULT 0,
  status TEXT DEFAULT 'Tersedia',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chats (
  id TEXT PRIMARY KEY,
  member1 TEXT NOT NULL,
  member2 TEXT NOT NULL,
  last_message TEXT DEFAULT '',
  last_message_at INTEGER DEFAULT 0,
  last_sender_id TEXT,
  wallpaper TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  sender_name TEXT NOT NULL,
  text TEXT DEFAULT '',
  media_url TEXT DEFAULT '',
  media_type TEXT DEFAULT '',
  media_name TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS statuses (
  id TEXT PRIMARY KEY,
  uid TEXT NOT NULL,
  user_name TEXT NOT NULL,
  user_photo TEXT DEFAULT '',
  verified INTEGER DEFAULT 0,
  media_url TEXT NOT NULL,
  media_type TEXT NOT NULL,
  caption TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS status_views (
  status_id TEXT NOT NULL,
  viewer_id TEXT NOT NULL,
  PRIMARY KEY (status_id, viewer_id)
);

CREATE TABLE IF NOT EXISTS calls (
  id TEXT PRIMARY KEY,
  uid TEXT NOT NULL,
  peer_id TEXT NOT NULL,
  peer_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, created_at);
CREATE INDEX IF NOT EXISTS idx_statuses_created ON statuses(created_at);
CREATE INDEX IF NOT EXISTS idx_chats_member1 ON chats(member1);
CREATE INDEX IF NOT EXISTS idx_chats_member2 ON chats(member2);
