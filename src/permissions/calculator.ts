import { createSignal } from "solid-js";

import { Channel, Client, Server, ServerMember } from "../index.js";

import {
  ALLOW_IN_TIMEOUT,
  DEFAULT_PERMISSION_DIRECT_MESSAGE,
  DEFAULT_PERMISSION_VIEW_ONLY,
  Permission,
  UserPermission,
} from "./definitions.js";

/**
 * Check whether `b` is present in `a`
 * @param a Input A
 * @param b Inputs (OR'd together)
 */
export function bitwiseAndEq(a: bigint, ...b: bigint[]): boolean {
  const value = b.reduce((prev, cur) => prev | cur, 0n);
  return (value & a) === value;
}

/**
 * Ferret: "view server as role". While set, your permissions in that one
 * server are worked out as if you only had these roles (an empty list means
 * just the default @everyone permissions), even if you own it. Only changes
 * what your app shows; the server still checks your real permissions.
 */
const [rolePreview, setRolePreview] = createSignal<
  { serverId: string; roleIds: string[] } | undefined
>();
export { rolePreview, setRolePreview };

/** A pretend member with only the previewed roles, for this server */
function previewMember(server: Server | undefined): ServerMember | undefined {
  const preview = rolePreview();
  if (!server || !preview || preview.serverId !== server.id) return undefined;
  const orderedRoles = preview.roleIds
    .map((id) => server.roles?.get(id))
    .filter((role) => role)
    .sort((a, b) => b!.rank! - a!.rank!);
  return {
    roles: preview.roleIds,
    orderedRoles,
    timeout: null,
  } as unknown as ServerMember;
}

/**
 * Calculate permissions against a given object
 * @param target Target object to check permissions against
 * @param options Additional options to use when calculating
 */
export function calculatePermission(
  client: Client,
  target: Channel | Server,
  options?: {
    /**
     * Pretend to be another ServerMember
     */
    member?: ServerMember;
  },
): bigint {
  // Ferret: previewing this server as a role
  if (!options?.member) {
    const server =
      target instanceof Server
        ? target
        : target.type === "TextChannel"
          ? target.server
          : undefined;
    const member = previewMember(server);
    if (member) options = { ...options, member };
  }

  const user = options?.member ? options?.member.user : client.user;
  if (user?.privileged) {
    return Permission.GrantAllSafe;
  }

  if (target instanceof Server) {
    // 1. Check if owner.
    if (target.ownerId === user?.id) {
      return Permission.GrantAllSafe;
    } else {
      // 2. Get ServerMember.
      const member = options?.member ??
        client.serverMembers.getByKey({
          user: user!.id,
          server: target.id,
        }) ?? { roles: null, timeout: null };

      if (!member) return 0n;

      // 3. Apply allows from default_permissions.
      let perm = BigInt(target.defaultPermissions);

      // 4. If user has roles, iterate in order.
      if (member.roles && target.roles) {
        // 5. Apply allows and denies from roles.
        const permissions = member.orderedRoles.map(
          (role) => role.permissions ?? { a: 0, d: 0 },
        );

        for (const permission of permissions) {
          perm = (perm | BigInt(permission.a)) & ~BigInt(permission.d);
        }
      }

      // 5. Revoke permissions if ServerMember is timed out.
      if (member.timeout && member.timeout > new Date()) {
        perm = perm & BigInt(ALLOW_IN_TIMEOUT);
      }

      return perm;
    }
  } else {
    // 1. Check channel type.
    switch (target.type) {
      case "SavedMessages":
        return Permission.GrantAllSafe;
      case "DirectMessage": {
        // 2. Determine user permissions.
        const user_permissions = target.recipient?.permission || 0;

        // 3. Check if the user can send messages.
        if (user_permissions & UserPermission.SendMessage) {
          return DEFAULT_PERMISSION_DIRECT_MESSAGE;
        } else {
          return DEFAULT_PERMISSION_VIEW_ONLY;
        }
      }
      case "Group": {
        // 2. Check if user is owner.
        if (target.ownerId === user!.id) {
          return Permission.GrantAllSafe;
        } else {
          // 3. Pull out group permissions.
          return target.permissions ?? DEFAULT_PERMISSION_DIRECT_MESSAGE;
        }
      }
      case "TextChannel": {
        // 2. Get server.
        const server = target.server;
        if (typeof server === "undefined") return 0n;

        // 3. If server owner, just grant all permissions.
        if (server.ownerId === user?.id) {
          return Permission.GrantAllSafe;
        } else {
          // 4. Get ServerMember.
          const member = options?.member ??
            client.serverMembers.getByKey({
              user: user!.id,
              server: server.id,
            }) ?? { roles: null, timeout: null };

          if (!member) return 0n;

          // 5. Calculate server base permissions.
          let perm = BigInt(calculatePermission(client, server, options));

          // 6. Apply default allows and denies for channel.
          if (target.defaultPermissions) {
            perm =
              (perm | BigInt(target.defaultPermissions.a)) &
              ~BigInt(target.defaultPermissions.d);
          }

          // 7. If user has roles, iterate in order.
          if (member.roles && target.rolePermissions && server.roles) {
            // 5. Apply allows and denies from roles.
            const roles = member.orderedRoles.map(({ id }) => id);

            for (const id of roles) {
              const override = target.rolePermissions[id];
              if (override) {
                perm = (perm | BigInt(override.a)) & ~BigInt(override.d);
              }
            }
          }

          // 8. Revoke permissions if ServerMember is timed out.
          if (member.timeout && member.timeout > new Date()) {
            perm = perm & BigInt(ALLOW_IN_TIMEOUT);
          }

          return perm;
        }
      }
    }

    return 0n;
  }
}
