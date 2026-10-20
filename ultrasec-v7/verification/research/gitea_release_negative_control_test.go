// Copyright 2026 UltraSec V7 researchers. SPDX-License-Identifier: MIT
// Public supplemental test only: copy into BOTH original upstream Git trees.
// Never modify the Gitea production code; do not treat this as an upstream test.
// Successful allowed/no-op operations are genuine negative *controls*, not GOLD.
package release

import (
    "strings"
    "testing"

    repo_model "gitea.dev/models/repo"
    "gitea.dev/models/unittest"
    user_model "gitea.dev/models/user"
    "gitea.dev/modules/gitrepo"
    "gitea.dev/modules/setting"
    testutil "gitea.dev/modules/test"
    "gitea.dev/services/attachment"

    "github.com/stretchr/testify/require"
)

// TestUltraSecReleaseAllowedRename is executed against original vulnerable
// and fixed source with the SAME allowlist and original database machinery.
// It proves a legitimate rename and a no-op are not falsely blocked.
func TestUltraSecReleaseAllowedRename(t *testing.T) {
    require.NoError(t, unittest.PrepareTestDatabase())
    user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
    repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
    gitRepo, err := gitrepo.OpenRepository(t.Context(), repo)
    require.NoError(t, err)
    defer gitRepo.Close()

    release := &repo_model.Release{
        RepoID: repo.ID,
        Repo: repo,
        PublisherID: user.ID,
        Publisher: user,
        TagName: "ultrasec-negative-allowlist",
        Target: "master",
        Title: "legitimate attachment edit",
        Note: "original Gitea source control",
        IsDraft: false,
        IsPrerelease: false,
        IsTag: false,
    }
    require.NoError(t, CreateRelease(gitRepo, release, nil, ""))
    payload := "non-sensitive-public-fixture"
    uploaded, err := attachment.NewAttachment(t.Context(), &repo_model.Attachment{
        RepoID: repo.ID, UploaderID: user.ID, Name: "allowed.zip",
    }, strings.NewReader(payload), int64(len(payload)))
    require.NoError(t, err)
    require.NoError(t, UpdateRelease(t.Context(), user, gitRepo, release,
        []string{uploaded.UUID}, nil, nil))

    defer testutil.MockVariableValue(&setting.Repository.Release.AllowedTypes, ".zip")()
    require.NoError(t, UpdateRelease(t.Context(), user, gitRepo, release,
        nil, nil, map[string]string{uploaded.UUID: "renamed.zip"}))
    release.Attachments = nil
    require.NoError(t, repo_model.GetReleaseAttachments(t.Context(), release))
    require.Len(t, release.Attachments, 1)
    require.Equal(t, uploaded.UUID, release.Attachments[0].UUID)
    require.Equal(t, "renamed.zip", release.Attachments[0].Name)
    t.Log("ULTRASEC_NEGATIVE_ALLOWED_RENAME=PASS")

    // Under the same restrictive allowlist, a harmless metadata-only update
    // must preserve the exact attachment identity and name.
    release.Note = "harmless metadata-only change"
    require.NoError(t, UpdateRelease(t.Context(), user, gitRepo, release,
        nil, nil, nil))
    release.Attachments = nil
    require.NoError(t, repo_model.GetReleaseAttachments(t.Context(), release))
    require.Len(t, release.Attachments, 1)
    require.Equal(t, uploaded.UUID, release.Attachments[0].UUID)
    require.Equal(t, "renamed.zip", release.Attachments[0].Name)
    t.Log("ULTRASEC_NEGATIVE_NOOP=PASS")
}
