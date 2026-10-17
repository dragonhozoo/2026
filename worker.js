// worker.js - Cloudflare Worker backend untuk WA2026

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// --- JWT helpers (HMAC SHA-256 manual, tanpa library) ---
async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64url(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return decodeURIComponent(escape(atob(str)));
}

async function createToken(payload, secret) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify(payload));
  const sig = await hmacSign(secret, header + '.' + body);
  return header + '.' + body + '.' + sig;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const sig = await hmacSign(secret, parts[0] + '.' + parts[1]);
    if (sig !== parts[2]) return null;
    return JSON.parse(base64urlDecode(parts[1]));
  } catch (e) { return null; }
}

async function hashPassword(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function uid() { return crypto.randomUUID(); }

async function getUserFromReq(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  return await verifyToken(token, env.JWT_SECRET);
}

// --- Main handler ---
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // AUTH
      if (path === '/api/register' && request.method === 'POST') {
        const { email, password, name } = await request.json();
        if (!email || !password || !name) return err('Email, password, nama wajib diisi');
        if (password.length < 6) return err('Password minimal 6 karakter');
        const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (existing) return err('Email sudah terdaftar');
        const id = uid();
        const hash = await hashPassword(password);
        await env.DB.prepare(
          'INSERT INTO users (id,email,password_hash,name,created_at) VALUES (?,?,?,?,?)'
        ).bind(id, email, hash, name, Date.now()).run();
        const token = await createToken({ uid: id, email }, env.JWT_SECRET);
        return json({ token, user: { uid: id, email, name, photoURL: '', verified: false, status: 'Tersedia' } });
      }

      if (path === '/api/login' && request.method === 'POST') {
        const { email, password } = await request.json();
        if (!email || !password) return err('Email dan password wajib diisi');
        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
        if (!user) return err('Akun tidak ditemukan');
        const hash = await hashPassword(password);
        if (hash !== user.password_hash) return err('Password salah');
        const token = await createToken({ uid: user.id, email: user.email }, env.JWT_SECRET);
        return json({
          token,
          user: {
            uid: user.id, email: user.email, name: user.name,
            photoURL: user.photo_url, verified: !!user.verified, status: user.status
          }
        });
      }

      // Semua endpoint di bawah butuh auth
      const authUser = await getUserFromReq(request, env);
      if (!authUser) return err('Unauthorized', 401);

      // GET ME
      if (path === '/api/me' && request.method === 'GET') {
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(authUser.uid).first();
        if (!user) return err('User tidak ditemukan', 404);
        return json({
          uid: user.id, email: user.email, name: user.name,
          photoURL: user.photo_url, verified: !!user.verified, status: user.status
        });
      }

      // UPDATE PROFILE
      if (path === '/api/profile' && request.method === 'PUT') {
        const { name, photoURL, verified, status } = await request.json();
        const updates = [];
        const values = [];
        if (name !== undefined) { updates.push('name = ?'); values.push(name); }
        if (photoURL !== undefined) { updates.push('photo_url = ?'); values.push(photoURL); }
        if (verified !== undefined) { updates.push('verified = ?'); values.push(verified ? 1 : 0); }
        if (status !== undefined) { updates.push('status = ?'); values.push(status); }
        if (!updates.length) return err('Tidak ada yang diupdate');
        values.push(authUser.uid);
        await env.DB.prepare('UPDATE users SET ' + updates.join(', ') + ' WHERE id = ?').bind(...values).run();
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(authUser.uid).first();
        return json({
          uid: user.id, email: user.email, name: user.name,
          photoURL: user.photo_url, verified: !!user.verified, status: user.status
        });
      }

      // Cari user by email
      if (path === '/api/users/find' && request.method === 'GET') {
        const email = url.searchParams.get('email');
        if (!email) return err('Email wajib');
        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
        if (!user) return err('User tidak ditemukan', 404);
        return json({
          uid: user.id, email: user.email, name: user.name,
          photoURL: user.photo_url, verified: !!user.verified, status: user.status
        });
      }

      // GET user by id (public info)
      if (path.startsWith('/api/users/') && request.method === 'GET') {
        const id = path.split('/')[3];
        if (!id) return err('ID wajib');
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
        if (!user) return err('User tidak ditemukan', 404);
        return json({
          uid: user.id, email: user.email, name: user.name,
          photoURL: user.photo_url, verified: !!user.verified, status: user.status
        });
      }

      // CHATS
      if (path === '/api/chats' && request.method === 'GET') {
        const chats = await env.DB.prepare(
          'SELECT * FROM chats WHERE member1 = ? OR member2 = ? ORDER BY last_message_at DESC'
        ).bind(authUser.uid, authUser.uid).all();
        const result = [];
        for (const c of chats.results) {
          const otherId = c.member1 === authUser.uid ? c.member2 : c.member1;
          const other = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(otherId).first();
          result.push({
            id: c.id, otherUid: otherId,
            otherName: other ? other.name : 'Pengguna',
            otherPhoto: other ? other.photo_url : '',
            otherVerified: other ? !!other.verified : false,
            lastMessage: c.last_message, lastMessageAt: c.last_message_at,
            wallpaper: c.wallpaper || ''
          });
        }
        return json(result);
      }

      if (path === '/api/chats' && request.method === 'POST') {
        const { otherUid } = await request.json();
        if (!otherUid) return err('otherUid wajib');
        if (otherUid === authUser.uid) return err('Tidak bisa chat diri sendiri');
        const existing = await env.DB.prepare(
          'SELECT * FROM chats WHERE (member1 = ? AND member2 = ?) OR (member1 = ? AND member2 = ?)'
        ).bind(authUser.uid, otherUid, otherUid, authUser.uid).first();
        if (existing) return json({ id: existing.id });
        const id = uid();
        await env.DB.prepare(
          'INSERT INTO chats (id,member1,member2,created_at) VALUES (?,?,?,?)'
        ).bind(id, authUser.uid, otherUid, Date.now()).run();
        return json({ id });
      }

      // Messages
      if (path.match(/^\/api\/chats\/[^/]+\/messages$/) && request.method === 'GET') {
        const chatId = path.split('/')[3];
        const msgs = await env.DB.prepare(
          'SELECT * FROM messages WHERE chat_id = ? ORDER BY created_at ASC LIMIT 500'
        ).bind(chatId).all();
        return json(msgs.results);
      }

      if (path.match(/^\/api\/chats\/[^/]+\/messages$/) && request.method === 'POST') {
        const chatId = path.split('/')[3];
        const { text, mediaUrl, mediaType, mediaName } = await request.json();
        const me = await env.DB.prepare('SELECT name FROM users WHERE id = ?').bind(authUser.uid).first();
        const id = uid();
        await env.DB.prepare(
          'INSERT INTO messages (id,chat_id,sender_id,sender_name,text,media_url,media_type,media_name,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
        ).bind(id, chatId, authUser.uid, me.name, text || '', mediaUrl || '', mediaType || '', mediaName || '', Date.now()).run();
        const preview = mediaUrl ? '📎 Media' : (text || '');
        await env.DB.prepare(
          'UPDATE chats SET last_message = ?, last_message_at = ?, last_sender_id = ? WHERE id = ?'
        ).bind(preview, Date.now(), authUser.uid, chatId).run();
        return json({ id });
      }

      // Wallpaper
      if (path.match(/^\/api\/chats\/[^/]+\/wallpaper$/) && request.method === 'PUT') {
        const chatId = path.split('/')[3];
        const { wallpaper } = await request.json();
        await env.DB.prepare('UPDATE chats SET wallpaper = ? WHERE id = ?').bind(wallpaper || '', chatId).run();
        return json({ ok: true });
      }

      // STATUSES
      if (path === '/api/statuses' && request.method === 'GET') {
        const cutoff = Date.now() - 24 * 60 * 60 * 1000;
        const statuses = await env.DB.prepare(
          'SELECT * FROM statuses WHERE created_at > ? ORDER BY created_at DESC LIMIT 100'
        ).bind(cutoff).all();
        const result = [];
        for (const s of statuses.results) {
          const views = await env.DB.prepare('SELECT viewer_id FROM status_views WHERE status_id = ?').bind(s.id).all();
          result.push({
            ...s,
            viewedBy: views.results.map(v => v.viewer_id)
          });
        }
        return json(result);
      }

      if (path === '/api/statuses' && request.method === 'POST') {
        const { mediaUrl, mediaType, caption } = await request.json();
        if (!mediaUrl) return err('mediaUrl wajib');
        const me = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(authUser.uid).first();
        const id = uid();
        await env.DB.prepare(
          'INSERT INTO statuses (id,uid,user_name,user_photo,verified,media_url,media_type,caption,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
        ).bind(id, authUser.uid, me.name, me.photo_url || '', me.verified || 0, mediaUrl, mediaType || 'image', caption || '', Date.now()).run();
        return json({ id });
      }

      if (path.match(/^\/api\/statuses\/[^/]+\/view$/) && request.method === 'POST') {
        const statusId = path.split('/')[3];
        await env.DB.prepare(
          'INSERT OR IGNORE INTO status_views (status_id, viewer_id) VALUES (?,?)'
        ).bind(statusId, authUser.uid).run();
        return json({ ok: true });
      }

      // CALLS
      if (path === '/api/calls' && request.method === 'GET') {
        const calls = await env.DB.prepare(
          'SELECT * FROM calls WHERE uid = ? ORDER BY created_at DESC LIMIT 50'
        ).bind(authUser.uid).all();
        return json(calls.results);
      }

      // UPLOAD ke R2
      if (path === '/api/upload' && request.method === 'POST') {
        const formData = await request.formData();
        const file = formData.get('file');
        const folder = formData.get('folder') || 'misc';
        if (!file) return err('File wajib');
        const ext = file.name.split('.').pop() || 'bin';
        const key = `${folder}/${uid()}_${Date.now()}.${ext}`;
        await env.BUCKET.put(key, file.stream(), {
          httpMetadata: { contentType: file.type || 'application/octet-stream' }
        });
        const publicUrl = `${url.origin}/r2/${key}`;
        return json({ url: publicUrl, key });
      }

      // Serve R2 public
      if (path.startsWith('/r2/') && request.method === 'GET') {
        const key = path.slice(4);
        const obj = await env.BUCKET.get(key);
        if (!obj) return err('File tidak ditemukan', 404);
        const headers = new Headers(CORS_HEADERS);
        obj.writeHttpMetadata(headers);
        return new Response(obj.body, { headers });
      }

      return err('Endpoint tidak ditemukan', 404);
    } catch (e) {
      console.error('Worker error:', e);
      return err('Internal error: ' + e.message, 500);
    }
  }
};
