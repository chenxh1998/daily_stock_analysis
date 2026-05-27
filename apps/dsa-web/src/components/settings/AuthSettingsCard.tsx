import type React from 'react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { authApi, type UserItem } from '../../api/auth';
import { getParsedApiError, isParsedApiError, type ParsedApiError } from '../../api/error';
import { useAuth } from '../../hooks';
import { Badge, Button, Input, Checkbox } from '../common';
import { SettingsAlert } from './SettingsAlert';
import { SettingsSectionCard } from './SettingsSectionCard';

function createNextModeLabel(authEnabled: boolean, desiredEnabled: boolean) {
  if (authEnabled && !desiredEnabled) {
    return '关闭认证';
  }
  if (!authEnabled && desiredEnabled) {
    return '开启认证';
  }
  return authEnabled ? '保持已开启' : '保持已关闭';
}

export const AuthSettingsCard: React.FC = () => {
  const { authEnabled, isAdmin, setupState, refreshStatus } = useAuth();
  const [desiredEnabled, setDesiredEnabled] = useState(authEnabled);
  const [currentPassword, setCurrentPassword] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | ParsedApiError | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // User management state
  const [users, setUsers] = useState<UserItem[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [deactivatingId, setDeactivatingId] = useState<number | null>(null);

  const isDirty = desiredEnabled !== authEnabled || currentPassword || password || passwordConfirm;
  const targetActionLabel = createNextModeLabel(authEnabled, desiredEnabled);

  const helperText = useMemo(() => {
    switch (setupState) {
      case 'no_password':
        return '系统尚未设置密码。启用认证前请先设置初始管理员密码，设置后请妥善保管。';
      case 'password_retained':
        return '系统已保留之前设置的管理员密码。输入当前密码即可快速重新启用认证。';
      case 'enabled':
        return !desiredEnabled
          ? '若当前登录会话仍有效，可直接关闭认证；若会话已失效，请输入当前管理员密码。'
          : '管理员认证已启用。如需更新密码，请使用下方的"修改密码"功能。';
      default:
        return '管理员认证可保护 Web 设置页及 API 接口，防止未经授权的访问。';
    }
  }, [setupState, desiredEnabled]);

  useEffect(() => {
    setDesiredEnabled(authEnabled);
  }, [authEnabled]);

  const resetForm = () => {
    setCurrentPassword('');
    setPassword('');
    setPasswordConfirm('');
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setSuccessMessage(null);

    // Initial setup validation
    if (setupState === 'no_password' && desiredEnabled) {
      if (!password) {
        setError('设置新密码是必填项');
        return;
      }
      if (password !== passwordConfirm) {
        setError('两次输入的新密码不一致');
        return;
      }
    }

    setIsSubmitting(true);
    try {
      await authApi.updateSettings(
        desiredEnabled,
        password.trim() || undefined,
        passwordConfirm.trim() || undefined,
        currentPassword.trim() || undefined,
      );
      await refreshStatus();
      setSuccessMessage(desiredEnabled ? '认证设置已更新' : '认证已关闭');
      resetForm();
    } catch (err: unknown) {
      setError(getParsedApiError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  const fetchUsers = useCallback(async () => {
    setUsersLoading(true);
    setUsersError(null);
    try {
      const data = await authApi.listUsers();
      setUsers(data.users);
    } catch (err: unknown) {
      setUsersError(getParsedApiError(err).message);
    } finally {
      setUsersLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAdmin && authEnabled) {
      void fetchUsers();
    }
  }, [isAdmin, authEnabled, fetchUsers]);

  const handleDeactivate = async (userId: number) => {
    setDeactivatingId(userId);
    try {
      await authApi.deactivateUser(userId);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    } catch (err: unknown) {
      setError(getParsedApiError(err));
    } finally {
      setDeactivatingId(null);
    }
  };

  return (
    <>
      <SettingsSectionCard
        title="认证与登录保护"
        description="管理管理员密码认证，保护您的系统配置安全。"
        actions={
          <Badge
            variant={authEnabled ? 'success' : 'default'}
            size="sm"
            className={authEnabled ? '' : 'border-[var(--settings-border)] bg-[var(--settings-surface-hover)] text-secondary-text'}
          >
            {authEnabled ? '已启用' : '未启用'}
          </Badge>
        }
      >
        <form className="space-y-4" onSubmit={handleSubmit}>
          <div className="rounded-xl border border-[var(--settings-border)] bg-[var(--settings-surface)] p-4 shadow-soft-card transition-[background-color,border-color] duration-200 hover:border-[var(--settings-border-strong)] hover:bg-[var(--settings-surface-hover)]">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="space-y-1">
                <p className="text-sm font-semibold text-foreground">管理员认证</p>
                <p className="text-xs leading-6 text-muted-text">{helperText}</p>
              </div>
              <Checkbox
                checked={desiredEnabled}
                disabled={isSubmitting}
                label={desiredEnabled ? '开启' : '关闭'}
                onChange={(event) => setDesiredEnabled(event.target.checked)}
                containerClassName="rounded-full border border-[var(--settings-border)] bg-[var(--settings-surface-hover)] px-4 py-2 shadow-soft-card transition-[background-color,border-color] duration-200 hover:border-[var(--settings-border-strong)] hover:bg-[var(--settings-surface)]"
              />
            </div>
          </div>

          {/* Password input fields logic based on setupState and desiredEnabled */}
          {(desiredEnabled || (authEnabled && !desiredEnabled)) && (
            <div className="grid gap-4 md:grid-cols-2">
              {/* Show Current Password if we have one and we're either re-enabling or turning off */}
              {(setupState === 'password_retained' && desiredEnabled) ||
               (setupState === 'enabled' && !desiredEnabled) ? (
                <div className="space-y-3">
                  <Input
                    label="当前管理员密码"
                    type="password"
                    allowTogglePassword
                    iconType="password"
                    value={currentPassword}
                    onChange={(event) => setCurrentPassword(event.target.value)}
                    autoComplete="current-password"
                    disabled={isSubmitting}
                    placeholder="请输入当前密码"
                    hint={setupState === 'password_retained' ? '输入旧密码以重新激活认证' : '关闭认证前可能需要验证身份'}
                  />
                </div>
              ) : null}

              {/* Show New Password fields only during initial setup */}
              {setupState === 'no_password' && desiredEnabled ? (
                <>
                  <div className="space-y-3">
                    <Input
                      label="设置管理员密码"
                      type="password"
                      allowTogglePassword
                      iconType="password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete="new-password"
                      disabled={isSubmitting}
                      placeholder="输入新密码 (至少 6 位)"
                    />
                  </div>
                  <div className="space-y-3">
                    <Input
                      label="确认新密码"
                      type="password"
                      allowTogglePassword
                      iconType="password"
                      value={passwordConfirm}
                      onChange={(event) => setPasswordConfirm(event.target.value)}
                      autoComplete="new-password"
                      disabled={isSubmitting}
                      placeholder="再次输入以确认"
                    />
                  </div>
                </>
              ) : null}
            </div>
          )}

          {error ? (
            isParsedApiError(error) ? (
              <SettingsAlert
                title="认证设置失败"
                message={error.message}
                variant="error"
              />
            ) : (
              <SettingsAlert title="认证设置失败" message={error} variant="error" />
            )
          ) : null}

          {successMessage ? (
            <SettingsAlert title="操作成功" message={successMessage} variant="success" />
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" variant="settings-primary" isLoading={isSubmitting} disabled={!isDirty}>
              {targetActionLabel}
            </Button>
            <Button
              type="button"
              variant="settings-secondary"
              onClick={() => {
                setDesiredEnabled(authEnabled);
                setError(null);
                setSuccessMessage(null);
                resetForm();
              }}
              disabled={isSubmitting || !isDirty}
            >
              还原
            </Button>
          </div>
        </form>
      </SettingsSectionCard>

      {/* User Management Section (admin only) */}
      {isAdmin && authEnabled && (
        <SettingsSectionCard
          title="用户管理"
          description="管理所有已注册的用户账户。"
          actions={
            <Button
              type="button"
              variant="settings-secondary"
              size="sm"
              isLoading={usersLoading}
              onClick={fetchUsers}
            >
              刷新
            </Button>
          }
        >
          {usersError ? (
            <SettingsAlert title="加载用户列表失败" message={usersError} variant="error" />
          ) : users.length === 0 && !usersLoading ? (
            <p className="text-sm text-muted-text">暂无用户数据</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--settings-border)] text-left text-xs text-muted-text">
                    <th className="pb-2 font-medium">用户名</th>
                    <th className="pb-2 font-medium">显示名称</th>
                    <th className="pb-2 font-medium">角色</th>
                    <th className="pb-2 font-medium">状态</th>
                    <th className="pb-2 font-medium">创建时间</th>
                    <th className="pb-2 font-medium">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id} className="border-b border-[var(--settings-border)]/50">
                      <td className="py-2 font-medium">{user.username}</td>
                      <td className="py-2 text-muted-text">{user.displayName || '-'}</td>
                      <td className="py-2">
                        {user.isAdmin ? (
                          <Badge variant="info" size="sm">管理员</Badge>
                        ) : (
                          <Badge variant="default" size="sm">普通用户</Badge>
                        )}
                      </td>
                      <td className="py-2">
                        {user.isActive ? (
                          <span className="text-emerald-600">活跃</span>
                        ) : (
                          <span className="text-muted-text">已停用</span>
                        )}
                      </td>
                      <td className="py-2 text-muted-text text-xs">
                        {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : '-'}
                      </td>
                      <td className="py-2">
                        {user.isActive && (
                          <Button
                            type="button"
                            variant="settings-secondary"
                            size="sm"
                            isLoading={deactivatingId === user.id}
                            onClick={() => handleDeactivate(user.id)}
                          >
                            停用
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SettingsSectionCard>
      )}
    </>
  );
};
