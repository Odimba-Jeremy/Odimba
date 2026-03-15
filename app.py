import os
import json
import uuid
import secrets
import re
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

# ==================== CONFIGURATION ====================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# CORS - Accepte toutes les origines (simplifié)
CORS(app)

# JWT
JWT_SECRET = os.environ.get('JWT_SECRET', app.config['SECRET_KEY'])
JWT_ALGORITHM = 'HS256'

# ==================== BASE DE DONNÉES JSON ====================
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

def read_db(filename):
    """Lit un fichier JSON"""
    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return []

def write_db(filename, data):
    """Écrit dans un fichier JSON"""
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# ==================== FONCTIONS JWT ====================
def decode_token(token):
    """Décode un token JWT"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except:
        return None

def token_required(f):
    """Décorateur pour routes protégées"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token manquant'}), 401
        
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Token invalide'}), 401
        
        request.user_id = payload.get('user_id')
        request.user_email = payload.get('email')
        
        return f(*args, **kwargs)
    return decorated

# ==================== FONCTIONS UTILISATEURS ====================
def find_user_by_id(user_id):
    """Trouve un utilisateur par ID"""
    users = read_db('users.json')
    for user in users:
        if user['id'] == user_id:
            return user
    return None

def update_user(user_id, updates):
    """Met à jour un utilisateur"""
    users = read_db('users.json')
    for i, user in enumerate(users):
        if user['id'] == user_id:
            users[i].update(updates)
            users[i]['updated_at'] = datetime.utcnow().isoformat()
            write_db('users.json', users)
            return users[i]
    return None

# ==================== ROUTES ====================
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})

# === PROFIL ===
@app.route('/me', methods=['GET'])
@token_required
def get_current_user():
    user = find_user_by_id(request.user_id)
    if not user:
        return jsonify({'error': 'Utilisateur non trouvé'}), 404
    
    return jsonify({
        'id': user['id'],
        'name': user['name'],
        'email': user['email'],
        'bio': user.get('bio', ''),
        'avatar': user.get('avatar', ''),
        'settings': user.get('settings', {'notifications': True, 'private_profile': False}),
        'stats': user.get('stats', {'posts': 0, 'likes': 0, 'friends': 0})
    })

@app.route('/me', methods=['PUT'])
@token_required
def update_current_user():
    data = request.get_json()
    user = find_user_by_id(request.user_id)
    
    if not user:
        return jsonify({'error': 'Utilisateur non trouvé'}), 404
    
    updates = {}
    if 'name' in data and data['name'].strip():
        updates['name'] = data['name'].strip()
    if 'bio' in data:
        updates['bio'] = data['bio'].strip()
    if 'email' in data and data['email'].strip():
        updates['email'] = data['email'].strip().lower()
    
    if updates:
        updated_user = update_user(user['id'], updates)
        return jsonify({
            'message': 'Profil mis à jour',
            'id': updated_user['id'],
            'name': updated_user['name'],
            'email': updated_user['email'],
            'bio': updated_user.get('bio', ''),
            'avatar': updated_user.get('avatar', '')
        })
    
    return jsonify({'message': 'Aucune modification'})

@app.route('/me/stats', methods=['GET'])
@token_required
def get_user_stats():
    posts = read_db(f'posts_{request.user_id}.json')
    total_likes = sum(len(p.get('likes', [])) for p in posts)
    
    return jsonify({
        'posts': len(posts),
        'likes': total_likes,
        'friends': 0
    })

@app.route('/me/settings', methods=['GET'])
@token_required
def get_user_settings():
    user = find_user_by_id(request.user_id)
    return jsonify(user.get('settings', {'notifications': True, 'private_profile': False}))

@app.route('/me/settings', methods=['PUT'])
@token_required
def update_user_settings():
    data = request.get_json()
    user = find_user_by_id(request.user_id)
    
    settings = user.get('settings', {})
    if 'notifications' in data:
        settings['notifications'] = bool(data['notifications'])
    if 'private_profile' in data:
        settings['private_profile'] = bool(data['private_profile'])
    
    update_user(user['id'], {'settings': settings})
    return jsonify({'message': 'Paramètres mis à jour', 'settings': settings})

# === POSTS ===
@app.route('/posts', methods=['GET'])
@token_required
def get_posts():
    all_posts = []
    users = read_db('users.json')
    
    for u in users:
        posts = read_db(f'posts_{u["id"]}.json')
        for p in posts:
            p['author_id'] = u['id']
            p['author_name'] = u['name']
            p['author_avatar'] = u.get('avatar', '')
            p['liked'] = request.user_id in p.get('likes', [])
            p['bookmarked'] = request.user_id in p.get('bookmarks', [])
            all_posts.append(p)
    
    all_posts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return jsonify(all_posts[:50])

@app.route('/posts', methods=['POST'])
@token_required
def create_post():
    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content or len(content) > 500:
        return jsonify({'error': 'Contenu invalide'}), 400
    
    posts = read_db(f'posts_{request.user_id}.json')
    new_post = {
        'id': str(uuid.uuid4()),
        'content': content,
        'created_at': datetime.utcnow().isoformat(),
        'likes': [],
        'bookmarks': [],
        'comments': []
    }
    
    posts.append(new_post)
    write_db(f'posts_{request.user_id}.json', posts)
    
    return jsonify({'message': 'Post créé', 'post': new_post}), 201

@app.route('/posts/<post_id>/like', methods=['POST'])
@token_required
def like_post(post_id):
    users = read_db('users.json')
    
    for user in users:
        posts = read_db(f'posts_{user["id"]}.json')
        for i, post in enumerate(posts):
            if post['id'] == post_id:
                likes = post.get('likes', [])
                
                if request.user_id in likes:
                    likes.remove(request.user_id)
                    action = 'unliked'
                else:
                    likes.append(request.user_id)
                    action = 'liked'
                
                posts[i]['likes'] = likes
                write_db(f'posts_{user["id"]}.json', posts)
                
                return jsonify({'message': f'Post {action}', 'liked': action == 'liked'})
    
    return jsonify({'error': 'Post non trouvé'}), 404

@app.route('/posts/<post_id>/bookmark', methods=['POST'])
@token_required
def bookmark_post(post_id):
    users = read_db('users.json')
    
    for user in users:
        posts = read_db(f'posts_{user["id"]}.json')
        for i, post in enumerate(posts):
            if post['id'] == post_id:
                bookmarks = post.get('bookmarks', [])
                
                if request.user_id in bookmarks:
                    bookmarks.remove(request.user_id)
                    action = 'retiré'
                else:
                    bookmarks.append(request.user_id)
                    action = 'ajouté'
                
                posts[i]['bookmarks'] = bookmarks
                write_db(f'posts_{user["id"]}.json', posts)
                
                return jsonify({'message': f'Favori {action}'})
    
    return jsonify({'error': 'Post non trouvé'}), 404

@app.route('/posts/<post_id>/comments', methods=['POST'])
@token_required
def add_comment(post_id):
    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content or len(content) > 500:
        return jsonify({'error': 'Commentaire invalide'}), 400
    
    user = find_user_by_id(request.user_id)
    users = read_db('users.json')
    
    for u in users:
        posts = read_db(f'posts_{u["id"]}.json')
        for i, post in enumerate(posts):
            if post['id'] == post_id:
                comments = post.get('comments', [])
                comments.append({
                    'id': str(uuid.uuid4()),
                    'author': user['name'],
                    'author_id': user['id'],
                    'author_avatar': user.get('avatar', ''),
                    'content': content,
                    'created_at': datetime.utcnow().isoformat()
                })
                posts[i]['comments'] = comments
                write_db(f'posts_{u["id"]}.json', posts)
                
                return jsonify({'message': 'Commentaire ajouté'})
    
    return jsonify({'error': 'Post non trouvé'}), 404

@app.route('/posts/search', methods=['POST'])
@token_required
def search_posts():
    data = request.get_json()
    query = data.get('query', '').strip().lower()
    
    if not query:
        return jsonify([])
    
    results = []
    users = read_db('users.json')
    
    for u in users:
        posts = read_db(f'posts_{u["id"]}.json')
        for p in posts:
            if query in p.get('content', '').lower():
                p['author_id'] = u['id']
                p['author_name'] = u['name']
                p['author_avatar'] = u.get('avatar', '')
                p['liked'] = request.user_id in p.get('likes', [])
                p['bookmarked'] = request.user_id in p.get('bookmarks', [])
                results.append(p)
    
    results.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return jsonify(results[:20])

@app.route('/posts/bookmarks', methods=['GET'])
@token_required
def get_bookmarked_posts():
    results = []
    users = read_db('users.json')
    
    for u in users:
        posts = read_db(f'posts_{u["id"]}.json')
        for p in posts:
            if request.user_id in p.get('bookmarks', []):
                p['author_id'] = u['id']
                p['author_name'] = u['name']
                p['author_avatar'] = u.get('avatar', '')
                p['liked'] = request.user_id in p.get('likes', [])
                p['bookmarked'] = True
                results.append(p)
    
    results.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return jsonify(results)

@app.route('/me/posts', methods=['GET'])
@token_required
def get_my_posts():
    posts = read_db(f'posts_{request.user_id}.json')
    
    for p in posts:
        p['liked'] = request.user_id in p.get('likes', [])
        p['bookmarked'] = request.user_id in p.get('bookmarks', [])
    
    posts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return jsonify(posts)

# === MESSAGES ===
@app.route('/messages/conversations', methods=['GET'])
@token_required
def get_conversations():
    conversations = []
    messages = read_db(f'messages_{request.user_id}.json')
    
    by_user = {}
    for msg in messages:
        other_id = msg['sender_id'] if msg['sender_id'] != request.user_id else msg['receiver_id']
        if other_id not in by_user:
            by_user[other_id] = []
        by_user[other_id].append(msg)
    
    for other_id, msgs in by_user.items():
        other_user = find_user_by_id(other_id)
        if other_user:
            last_msg = max(msgs, key=lambda x: x.get('created_at', ''))
            unread = sum(1 for m in msgs if not m.get('read', False) and m['receiver_id'] == request.user_id)
            
            conversations.append({
                'user_id': other_id,
                'name': other_user['name'],
                'avatar': other_user.get('avatar', ''),
                'last_message': last_msg['content'][:50],
                'last_message_at': last_msg['created_at'],
                'unread': unread > 0
            })
    
    conversations.sort(key=lambda x: x['last_message_at'], reverse=True)
    return jsonify(conversations)

@app.route('/messages/<user_id>', methods=['GET'])
@token_required
def get_messages(user_id):
    messages = read_db(f'messages_{request.user_id}.json')
    
    conv_messages = [
        m for m in messages 
        if (m['sender_id'] == user_id and m['receiver_id'] == request.user_id) or
           (m['sender_id'] == request.user_id and m['receiver_id'] == user_id)
    ]
    
    conv_messages.sort(key=lambda x: x.get('created_at', ''))
    other_user = find_user_by_id(user_id)
    
    return jsonify({
        'user': {
            'id': other_user['id'],
            'name': other_user['name'],
            'avatar': other_user.get('avatar', '')
        },
        'messages': conv_messages
    })

@app.route('/messages/<user_id>', methods=['POST'])
@token_required
def send_message(user_id):
    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content or len(content) > 1000:
        return jsonify({'error': 'Message invalide'}), 400
    
    other_user = find_user_by_id(user_id)
    if not other_user:
        return jsonify({'error': 'Utilisateur non trouvé'}), 404
    
    message = {
        'id': str(uuid.uuid4()),
        'sender_id': request.user_id,
        'receiver_id': user_id,
        'content': content,
        'created_at': datetime.utcnow().isoformat(),
        'read': False
    }
    
    for uid in [request.user_id, user_id]:
        msgs = read_db(f'messages_{uid}.json')
        msgs.append(message)
        write_db(f'messages_{uid}.json', msgs)
    
    return jsonify({'message': 'Message envoyé', 'sent_message': message}), 201

@app.route('/messages/<user_id>/read', methods=['POST'])
@token_required
def mark_messages_read(user_id):
    messages = read_db(f'messages_{request.user_id}.json')
    
    for msg in messages:
        if msg['sender_id'] == user_id and msg['receiver_id'] == request.user_id:
            msg['read'] = True
    
    write_db(f'messages_{request.user_id}.json', messages)
    return jsonify({'message': 'Messages marqués comme lus'})

@app.route('/messages/unread-count', methods=['GET'])
@token_required
def get_unread_count():
    messages = read_db(f'messages_{request.user_id}.json')
    count = sum(1 for m in messages if not m.get('read', False) and m['receiver_id'] == request.user_id)
    return jsonify({'count': count})

# === NOTIFICATIONS ===
@app.route('/notifications', methods=['GET'])
@token_required
def get_notifications():
    notifs = read_db(f'notifications_{request.user_id}.json')
    notifs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return jsonify(notifs[:50])

@app.route('/notifications/unread-count', methods=['GET'])
@token_required
def get_unread_notifications_count():
    notifs = read_db(f'notifications_{request.user_id}.json')
    count = sum(1 for n in notifs if not n.get('read', False))
    return jsonify({'count': count})

@app.route('/notifications/read-all', methods=['POST'])
@token_required
def mark_all_notifications_read():
    notifs = read_db(f'notifications_{request.user_id}.json')
    for n in notifs:
        n['read'] = True
    write_db(f'notifications_{request.user_id}.json', notifs)
    return jsonify({'message': 'Notifications marquées comme lues'})

# === UTILISATEURS ===
@app.route('/users/search', methods=['POST'])
@token_required
def search_users():
    data = request.get_json()
    query = data.get('query', '').strip().lower()
    
    if not query:
        return jsonify([])
    
    users = read_db('users.json')
    results = []
    
    for u in users:
        if u['id'] != request.user_id:
            if query in u.get('name', '').lower() or query in u.get('email', '').lower():
                results.append({
                    'id': u['id'],
                    'name': u['name'],
                    'bio': u.get('bio', ''),
                    'avatar': u.get('avatar', '')
                })
    
    return jsonify(results[:20])

@app.route('/logout', methods=['POST'])
@token_required
def logout():
    return jsonify({'message': 'Déconnexion réussie'})

# ==================== DÉMARRAGE ====================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
