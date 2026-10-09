# Team workspaces

Team entitlements can create shared workspaces at `/workspaces`. Campaigns created with a workspace are visible to active members of that workspace. Campaigns without a workspace retain their existing ownership behavior.

## Roles

- **Owner**: full workspace membership administration; cannot be removed or changed through role editing.
- **Admin**: can add members, change member access indirectly by removal, and manage campaigns; cannot appoint or manage admins.
- **Member**: can view and modify shared campaigns.
- **Viewer**: can view shared campaigns and cannot change campaign state or settings.

Only owners and admins can add or remove members. Members must already have an active AihaX account; this version does not send email invitations or provision accounts. New accounts can be added after their first sign-in.

## Seats and plan enforcement

The service validates the workspace creator's cached signed entitlement when adding members. Team plans allow five total members, including the owner. Founder, Agency, and Enterprise entitlements are not capped by this endpoint. Entitlement verification fails closed if the signed cache is missing, invalid, or expired.

## API

- `GET /api/organizations` lists the current user's workspaces.
- `POST /api/organizations` creates a workspace (Team entitlement required).
- `GET /api/organizations/{id}/members` lists members visible to a workspace member.
- `POST /api/organizations/{id}/members` adds an existing active account by email.
- `PATCH /api/organizations/{id}/members/{user_id}` changes a non-owner role.
- `DELETE /api/organizations/{id}/members/{user_id}` removes a non-owner member.

Membership checks are enforced by the backend. UI hiding is not used as an authorization boundary.
