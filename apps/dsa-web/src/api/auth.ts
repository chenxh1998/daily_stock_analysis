import apiClient from './index';

export type AuthStatusResponse = {
  authEnabled: boolean;
  loggedIn: boolean;
  userId?: number | null;
  username?: string | null;
  displayName?: string | null;
  isAdmin?: boolean;
  passwordSet?: boolean;
  passwordChangeable?: boolean;
  setupState: 'enabled' | 'password_retained' | 'no_password';
};

export type UserItem = {
  id: number;
  username: string;
  displayName: string | null;
  isAdmin: boolean;
  isActive: boolean;
  createdAt: string | null;
};

export type UsersListResponse = {
  users: UserItem[];
};

export const authApi = {
  async getStatus(): Promise<AuthStatusResponse> {
    const { data } = await apiClient.get<AuthStatusResponse>('/api/v1/auth/status');
    return data;
  },

  async updateSettings(
    authEnabled: boolean,
    password?: string,
    passwordConfirm?: string,
    currentPassword?: string
  ): Promise<AuthStatusResponse> {
    const body: {
      authEnabled: boolean;
      password?: string;
      passwordConfirm?: string;
      currentPassword?: string;
    } = { authEnabled };
    if (password !== undefined) {
      body.password = password;
    }
    if (passwordConfirm !== undefined) {
      body.passwordConfirm = passwordConfirm;
    }
    if (currentPassword !== undefined) {
      body.currentPassword = currentPassword;
    }
    const { data } = await apiClient.post<AuthStatusResponse>('/api/v1/auth/settings', body);
    return data;
  },

  async login(username: string, password: string, passwordConfirm?: string): Promise<void> {
    const body: { username: string; password: string; passwordConfirm?: string } = {
      username,
      password,
    };
    if (passwordConfirm !== undefined) {
      body.passwordConfirm = passwordConfirm;
    }
    await apiClient.post('/api/v1/auth/login', body);
  },

  async register(username: string, password: string, passwordConfirm: string): Promise<void> {
    await apiClient.post('/api/v1/auth/register', {
      username,
      password,
      passwordConfirm,
    });
  },

  async changePassword(
    currentPassword: string,
    newPassword: string,
    newPasswordConfirm: string
  ): Promise<void> {
    await apiClient.post('/api/v1/auth/change-password', {
      currentPassword,
      newPassword,
      newPasswordConfirm,
    });
  },

  async logout(): Promise<void> {
    await apiClient.post('/api/v1/auth/logout');
  },

  async listUsers(): Promise<UsersListResponse> {
    const { data } = await apiClient.get<UsersListResponse>('/api/v1/auth/users');
    return data;
  },

  async deactivateUser(userId: number): Promise<void> {
    await apiClient.post(`/api/v1/auth/users/${userId}/deactivate`);
  },
};
