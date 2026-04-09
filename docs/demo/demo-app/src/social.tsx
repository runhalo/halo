// Social features
import React from 'react';

export function UserProfile({ user }) {
  return (
    <div>
      <h2>{user.name}</h2>
      <p>Followers: {user.follower_count}</p>
      <p>Likes: {user.like_count}</p>
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
    </div>
  );
}

// Chat without content filtering
export function ChatRoom({ messages }) {
  const sendMessage = (text: string) => {
    fetch('/api/chat/send', { method: 'POST', body: JSON.stringify({ text, timestamp: Date.now() }) });
  };
  return <div>{messages.map(m => <p key={m.id}>{m.text}</p>)}</div>;
}
