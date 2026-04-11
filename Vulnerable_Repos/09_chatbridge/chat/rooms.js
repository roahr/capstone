const activeRooms = new Map();

function joinRoom(roomName, clientId, username) {
  if (!activeRooms.has(roomName)) {
    activeRooms.set(roomName, new Map());
  }

  const room = activeRooms.get(roomName);
  room.set(clientId, {
    username,
    joinedAt: Date.now(),
  });

  return { room: roomName, members: room.size };
}

function leaveRoom(roomName, clientId) {
  if (roomName) {
    const room = activeRooms.get(roomName);
    if (room) {
      room.delete(clientId);
      if (room.size === 0) {
        activeRooms.delete(roomName);
      }
    }
    return;
  }

  for (const [name, room] of activeRooms) {
    if (room.has(clientId)) {
      room.delete(clientId);
      if (room.size === 0) {
        activeRooms.delete(name);
      }
    }
  }
}

function getRoomMembers(roomName) {
  const room = activeRooms.get(roomName);
  if (!room) return [];

  return Array.from(room.values()).map((m) => ({
    username: m.username,
    joinedAt: new Date(m.joinedAt).toISOString(),
  }));
}

function listRooms() {
  const rooms = [];
  for (const [name, members] of activeRooms) {
    rooms.push({ name, memberCount: members.size });
  }
  return rooms;
}

module.exports = { joinRoom, leaveRoom, getRoomMembers, listRooms };
