import React, { useState } from 'react';
import { Lock, AlertTriangle } from 'lucide-react';
import './WorkspaceAuthModal.css';

const WorkspaceAuthModal = ({ workspace, onAuthenticate, onClose, loading }) => {
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!password.trim()) {
            setError('Password is required');
            return;
        }
        setError('');
        onAuthenticate(password);
    };

    return (
        <div className="workspace-auth-overlay">
            <div className="workspace-auth-modal">
                <div className="auth-modal-header">
                    <div className="auth-icon">
                        <Lock className="h-8 w-8 text-blue-500" />
                    </div>
                    <h2>Workspace Authentication Required</h2>
                    <p>Enter the password to access "{workspace.name}"</p>
                </div>

                <form onSubmit={handleSubmit} className="auth-modal-form">
                    <div className="form-group">
                        <label htmlFor="workspace-password">Workspace Password</label>
                        <input
                            id="workspace-password"
                            type="password"
                            value={password}
                            onChange={(e) => {
                                setPassword(e.target.value);
                                setError('');
                            }}
                            placeholder="Enter workspace password"
                            className={error ? 'error' : ''}
                            disabled={loading}
                        />
                        {error && (
                            <div className="error-message">
                                <AlertTriangle className="h-4 w-4" />
                                <span>{error}</span>
                            </div>
                        )}
                    </div>

                    <div className="auth-modal-actions">
                        <button 
                            type="button" 
                            onClick={onClose}
                            className="cancel-btn"
                            disabled={loading}
                        >
                            Cancel
                        </button>
                        <button 
                            type="submit" 
                            className="authenticate-btn"
                            disabled={loading}
                        >
                            {loading ? (
                                <>
                                    <div className="loading-spinner"></div>
                                    Authenticating...
                                </>
                            ) : (
                                'Authenticate'
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default WorkspaceAuthModal;