import React, { useState } from 'react';
import { useAuth, useUser } from '@rust-auth-service/react-hooks';

const UserProfile: React.FC = () => {
  const { logout } = useAuth();
  const { user, loading, error, updateProfile, clearError } = useUser();
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    first_name: user?.first_name || '',
    last_name: user?.last_name || '',
    email: user?.email || '',
  });

  React.useEffect(() => {
    if (user) {
      setFormData({
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
      });
    }
  }, [user]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();

    try {
      await updateProfile(formData);
      setIsEditing(false);
    } catch (error) {
      // Error is handled by the hook
    }
  };

  const handleCancel = () => {
    setIsEditing(false);
    if (user) {
      setFormData({
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
      });
    }
    clearError();
  };

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  if (!user) {
    return <div>No user data available</div>;
  }

  return (
    <div className="user-profile">
      <div className="profile-header">
        <h2>Welcome, {user.first_name} {user.last_name}!</h2>
        <div className="profile-actions">
          <button
            onClick={() => setIsEditing(!isEditing)}
            className="edit-button"
            disabled={loading}
          >
            {isEditing ? 'Cancel' : 'Edit Profile'}
          </button>
          <button onClick={handleLogout} className="logout-button">
            Logout
          </button>
        </div>
      </div>

      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      {isEditing ? (
        <form onSubmit={handleSubmit} className="profile-form">
          <div className="form-row">
            <div className="form-group">
              <label htmlFor="profile-first-name">First Name</label>
              <input
                id="profile-first-name"
                name="first_name"
                type="text"
                value={formData.first_name}
                onChange={handleChange}
                required
                disabled={loading}
              />
            </div>

            <div className="form-group">
              <label htmlFor="profile-last-name">Last Name</label>
              <input
                id="profile-last-name"
                name="last_name"
                type="text"
                value={formData.last_name}
                onChange={handleChange}
                required
                disabled={loading}
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="profile-email">Email</label>
            <input
              id="profile-email"
              name="email"
              type="email"
              value={formData.email}
              onChange={handleChange}
              required
              disabled={loading}
            />
          </div>

          <div className="form-actions">
            <button type="submit" disabled={loading} className="save-button">
              {loading ? (
                <>
                  <span className="spinner small"></span>
                  Saving...
                </>
              ) : (
                'Save Changes'
              )}
            </button>
            <button 
              type="button" 
              onClick={handleCancel} 
              className="cancel-button"
              disabled={loading}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="profile-info">
          <div className="info-group">
            <label>Name</label>
            <p>{user.first_name} {user.last_name}</p>
          </div>

          <div className="info-group">
            <label>Email</label>
            <p>{user.email}</p>
          </div>

          <div className="info-group">
            <label>Role</label>
            <span className="role-badge">{user.role}</span>
          </div>

          <div className="info-group">
            <label>Status</label>
            <div className="status-badges">
              <span className={`status-badge ${user.is_active ? 'active' : 'inactive'}`}>
                {user.is_active ? '✅ Active' : '❌ Inactive'}
              </span>
              <span className={`status-badge ${user.email_verified ? 'verified' : 'unverified'}`}>
                {user.email_verified ? '✅ Verified' : '⏳ Unverified'}
              </span>
            </div>
          </div>

          <div className="info-group">
            <label>Member Since</label>
            <p>{new Date(user.created_at).toLocaleDateString()}</p>
          </div>

          {user.last_login && (
            <div className="info-group">
              <label>Last Login</label>
              <p>{new Date(user.last_login).toLocaleString()}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default UserProfile;