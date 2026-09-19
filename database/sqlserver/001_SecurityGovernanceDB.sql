/*
  SecurityGovernanceDB - audit-first, history-first SQL Server baseline.
  This script is additive and isolated from the current application runtime.
  It is intentionally rerunnable only against a new database.

  Conventions:
    * All identifiers are UNIQUEIDENTIFIER and all timestamps are UTC.
    * Business tables are append-only from the application perspective.
    * State changes are represented by a new history/event row.
    * Deletes are represented by IsDeleted/DeletedDate/DeletedBy.
    * The API must set SESSION_CONTEXT keys: UserId, UserName, SessionId,
      IPAddress, Browser before executing a business transaction.
*/

IF DB_ID(N'SecurityGovernanceDB') IS NULL
    EXEC(N'CREATE DATABASE SecurityGovernanceDB');
GO
USE SecurityGovernanceDB;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'audit') EXEC(N'CREATE SCHEMA audit');
IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'history') EXEC(N'CREATE SCHEMA history');
IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'workflow') EXEC(N'CREATE SCHEMA workflow');
IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'security') EXEC(N'CREATE SCHEMA security');
IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'compliance') EXEC(N'CREATE SCHEMA compliance');
GO

CREATE TABLE security.Users (
    UserId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Users PRIMARY KEY,
    UserName NVARCHAR(256) NOT NULL,
    DisplayName NVARCHAR(256) NULL,
    Email NVARCHAR(320) NULL,
    IsActive BIT NOT NULL CONSTRAINT DF_Users_IsActive DEFAULT 1,
    CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_Users_CreatedDate DEFAULT SYSUTCDATETIME()
);
CREATE TABLE dbo.Applications (
    ApplicationId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Applications PRIMARY KEY,
    Mnemonic NVARCHAR(32) NOT NULL, ApplicationName NVARCHAR(256) NOT NULL,
    BusinessUnit NVARCHAR(256) NULL, ApplicationOwner UNIQUEIDENTIFIER NULL,
    Description NVARCHAR(MAX) NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_Applications_CreatedDate DEFAULT SYSUTCDATETIME(),
    CreatedBy UNIQUEIDENTIFIER NOT NULL, Status NVARCHAR(32) NOT NULL CONSTRAINT DF_Applications_Status DEFAULT N'ACTIVE',
    VersionNo INT NOT NULL CONSTRAINT DF_Applications_Version DEFAULT 1,
    IsDeleted BIT NOT NULL CONSTRAINT DF_Applications_IsDeleted DEFAULT 0, DeletedDate DATETIME2(7) NULL, DeletedBy UNIQUEIDENTIFIER NULL,
    CONSTRAINT UQ_Applications_Mnemonic UNIQUE (Mnemonic), CONSTRAINT FK_Applications_Owner FOREIGN KEY (ApplicationOwner) REFERENCES security.Users(UserId),
    CONSTRAINT FK_Applications_CreatedBy FOREIGN KEY (CreatedBy) REFERENCES security.Users(UserId)
);
CREATE TABLE dbo.Repositories (
    RepositoryId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Repositories PRIMARY KEY,
    ApplicationId UNIQUEIDENTIFIER NOT NULL, RepositoryName NVARCHAR(256) NOT NULL, RepositoryType NVARCHAR(64) NOT NULL,
    GitUrl NVARCHAR(2048) NULL, Branch NVARCHAR(256) NULL, LocalPath NVARCHAR(2048) NULL,
    CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_Repositories_CreatedDate DEFAULT SYSUTCDATETIME(), CreatedBy UNIQUEIDENTIFIER NOT NULL,
    VersionNo INT NOT NULL CONSTRAINT DF_Repositories_Version DEFAULT 1, IsDeleted BIT NOT NULL CONSTRAINT DF_Repositories_IsDeleted DEFAULT 0,
    DeletedDate DATETIME2(7) NULL, DeletedBy UNIQUEIDENTIFIER NULL,
    CONSTRAINT FK_Repositories_Application FOREIGN KEY (ApplicationId) REFERENCES dbo.Applications(ApplicationId),
    CONSTRAINT FK_Repositories_CreatedBy FOREIGN KEY (CreatedBy) REFERENCES security.Users(UserId)
);
CREATE TABLE dbo.ScanJobs (
    ScanId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_ScanJobs PRIMARY KEY, RepositoryId UNIQUEIDENTIFIER NOT NULL,
    ScanType NVARCHAR(64) NOT NULL, ScanEngine NVARCHAR(128) NOT NULL, RequestedBy UNIQUEIDENTIFIER NOT NULL,
    StartedTime DATETIME2(7) NULL, CompletedTime DATETIME2(7) NULL, ScanStatus NVARCHAR(32) NOT NULL,
    CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_ScanJobs_CreatedDate DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_ScanJobs_Repository FOREIGN KEY (RepositoryId) REFERENCES dbo.Repositories(RepositoryId), CONSTRAINT FK_ScanJobs_User FOREIGN KEY (RequestedBy) REFERENCES security.Users(UserId)
);
CREATE TABLE dbo.ScanResults (
    ScanResultId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_ScanResults PRIMARY KEY, ScanId UNIQUEIDENTIFIER NOT NULL,
    ResultVersion INT NOT NULL, ResultJson NVARCHAR(MAX) NOT NULL, FindingsCount INT NOT NULL CONSTRAINT DF_ScanResults_Count DEFAULT 0,
    CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_ScanResults_Created DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_ScanResults_Scan FOREIGN KEY (ScanId) REFERENCES dbo.ScanJobs(ScanId), CONSTRAINT UQ_ScanResults_Version UNIQUE (ScanId, ResultVersion)
);
CREATE TABLE dbo.Finding (
    FindingId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Finding PRIMARY KEY, ApplicationId UNIQUEIDENTIFIER NOT NULL, RepositoryId UNIQUEIDENTIFIER NOT NULL, ScanId UNIQUEIDENTIFIER NOT NULL,
    Title NVARCHAR(512) NOT NULL, Severity NVARCHAR(32) NOT NULL, Category NVARCHAR(128) NOT NULL, Description NVARCHAR(MAX) NULL,
    Status NVARCHAR(32) NOT NULL, AssignedTo UNIQUEIDENTIFIER NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_Finding_Created DEFAULT SYSUTCDATETIME(),
    VersionNo INT NOT NULL CONSTRAINT DF_Finding_Version DEFAULT 1, IsDeleted BIT NOT NULL CONSTRAINT DF_Finding_IsDeleted DEFAULT 0,
    CONSTRAINT FK_Finding_App FOREIGN KEY (ApplicationId) REFERENCES dbo.Applications(ApplicationId), CONSTRAINT FK_Finding_Repo FOREIGN KEY (RepositoryId) REFERENCES dbo.Repositories(RepositoryId), CONSTRAINT FK_Finding_Scan FOREIGN KEY (ScanId) REFERENCES dbo.ScanJobs(ScanId), CONSTRAINT FK_Finding_Assignee FOREIGN KEY (AssignedTo) REFERENCES security.Users(UserId)
);

CREATE TABLE history.FindingHistory (
    HistoryId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_FindingHistory PRIMARY KEY, FindingId UNIQUEIDENTIFIER NOT NULL,
    PreviousStatus NVARCHAR(32) NULL, NewStatus NVARCHAR(32) NULL, UserId UNIQUEIDENTIFIER NOT NULL, Action NVARCHAR(64) NOT NULL,
    Reason NVARCHAR(MAX) NULL, PreviousValue NVARCHAR(MAX) NULL, NewValue NVARCHAR(MAX) NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_FindingHistory_Created DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_FindingHistory_Finding FOREIGN KEY (FindingId) REFERENCES dbo.Finding(FindingId), CONSTRAINT FK_FindingHistory_User FOREIGN KEY (UserId) REFERENCES security.Users(UserId)
);
CREATE TABLE dbo.FindingComments (CommentId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_FindingComments PRIMARY KEY, FindingId UNIQUEIDENTIFIER NOT NULL, Comment NVARCHAR(MAX) NOT NULL, CreatedBy UNIQUEIDENTIFIER NOT NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_FindingComments_Created DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_FindingComments_Finding FOREIGN KEY (FindingId) REFERENCES dbo.Finding(FindingId), CONSTRAINT FK_FindingComments_User FOREIGN KEY (CreatedBy) REFERENCES security.Users(UserId));
CREATE TABLE dbo.FindingEvidence (EvidenceId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_FindingEvidence PRIMARY KEY, FindingId UNIQUEIDENTIFIER NOT NULL, EvidenceType NVARCHAR(64) NOT NULL, StorageUri NVARCHAR(2048) NOT NULL, ContentHash VARBINARY(64) NULL, UploadedBy UNIQUEIDENTIFIER NOT NULL, UploadedDate DATETIME2(7) NOT NULL CONSTRAINT DF_FindingEvidence_Uploaded DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_FindingEvidence_Finding FOREIGN KEY (FindingId) REFERENCES dbo.Finding(FindingId), CONSTRAINT FK_FindingEvidence_User FOREIGN KEY (UploadedBy) REFERENCES security.Users(UserId));
CREATE TABLE dbo.Remediation (RemediationId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Remediation PRIMARY KEY, FindingId UNIQUEIDENTIFIER NOT NULL, RepositoryId UNIQUEIDENTIFIER NOT NULL, GeneratedCode NVARCHAR(MAX) NULL, RecommendedFix NVARCHAR(MAX) NOT NULL, Status NVARCHAR(32) NOT NULL, CreatedBy UNIQUEIDENTIFIER NOT NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_Remediation_Created DEFAULT SYSUTCDATETIME(), VersionNo INT NOT NULL CONSTRAINT DF_Remediation_Version DEFAULT 1, CONSTRAINT FK_Remediation_Finding FOREIGN KEY (FindingId) REFERENCES dbo.Finding(FindingId), CONSTRAINT FK_Remediation_Repo FOREIGN KEY (RepositoryId) REFERENCES dbo.Repositories(RepositoryId), CONSTRAINT FK_Remediation_User FOREIGN KEY (CreatedBy) REFERENCES security.Users(UserId));
CREATE TABLE history.RemediationHistory (HistoryId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_RemediationHistory PRIMARY KEY, RemediationId UNIQUEIDENTIFIER NOT NULL, PreviousStatus NVARCHAR(32) NULL, NewStatus NVARCHAR(32) NULL, PreviousValue NVARCHAR(MAX) NULL, NewValue NVARCHAR(MAX) NULL, UserId UNIQUEIDENTIFIER NOT NULL, Action NVARCHAR(64) NOT NULL, Reason NVARCHAR(MAX) NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_RemediationHistory_Created DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_RemediationHistory_Remediation FOREIGN KEY (RemediationId) REFERENCES dbo.Remediation(RemediationId), CONSTRAINT FK_RemediationHistory_User FOREIGN KEY (UserId) REFERENCES security.Users(UserId));
CREATE TABLE dbo.CodeChange (ChangeId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_CodeChange PRIMARY KEY, RepositoryId UNIQUEIDENTIFIER NOT NULL, BranchName NVARCHAR(256) NOT NULL, CommitId NVARCHAR(128) NULL, FilePath NVARCHAR(2048) NOT NULL, BeforeCode NVARCHAR(MAX) NULL, AfterCode NVARCHAR(MAX) NULL, GeneratedRemediation BIT NOT NULL CONSTRAINT DF_CodeChange_Generated DEFAULT 0, Author UNIQUEIDENTIFIER NOT NULL, [Timestamp] DATETIME2(7) NOT NULL CONSTRAINT DF_CodeChange_Timestamp DEFAULT SYSUTCDATETIME(), ApprovalStatus NVARCHAR(32) NOT NULL, RelatedFindingId UNIQUEIDENTIFIER NULL, CONSTRAINT FK_CodeChange_Repo FOREIGN KEY (RepositoryId) REFERENCES dbo.Repositories(RepositoryId), CONSTRAINT FK_CodeChange_Author FOREIGN KEY (Author) REFERENCES security.Users(UserId), CONSTRAINT FK_CodeChange_Finding FOREIGN KEY (RelatedFindingId) REFERENCES dbo.Finding(FindingId));
CREATE TABLE history.CodeChangeHistory (HistoryId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_CodeChangeHistory PRIMARY KEY, ChangeId UNIQUEIDENTIFIER NOT NULL, PreviousValue NVARCHAR(MAX) NULL, NewValue NVARCHAR(MAX) NULL, Action NVARCHAR(64) NOT NULL, UserId UNIQUEIDENTIFIER NOT NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_CodeChangeHistory_Created DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_CodeChangeHistory_Change FOREIGN KEY (ChangeId) REFERENCES dbo.CodeChange(ChangeId), CONSTRAINT FK_CodeChangeHistory_User FOREIGN KEY (UserId) REFERENCES security.Users(UserId));
CREATE TABLE dbo.PullRequest (PRId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_PullRequest PRIMARY KEY, RepositoryId UNIQUEIDENTIFIER NOT NULL, PRNumber NVARCHAR(64) NOT NULL, SourceBranch NVARCHAR(256) NOT NULL, TargetBranch NVARCHAR(256) NOT NULL, CreatedBy UNIQUEIDENTIFIER NOT NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_PullRequest_Created DEFAULT SYSUTCDATETIME(), MergeStatus NVARCHAR(32) NOT NULL, CONSTRAINT FK_PR_Repo FOREIGN KEY (RepositoryId) REFERENCES dbo.Repositories(RepositoryId), CONSTRAINT FK_PR_User FOREIGN KEY (CreatedBy) REFERENCES security.Users(UserId));
CREATE TABLE history.PullRequestHistory (PRHistoryId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_PRHistory PRIMARY KEY, PRId UNIQUEIDENTIFIER NOT NULL, Action NVARCHAR(64) NOT NULL, Comment NVARCHAR(MAX) NULL, Reviewer UNIQUEIDENTIFIER NULL, [Timestamp] DATETIME2(7) NOT NULL CONSTRAINT DF_PRHistory_Timestamp DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_PRHistory_PR FOREIGN KEY (PRId) REFERENCES dbo.PullRequest(PRId), CONSTRAINT FK_PRHistory_User FOREIGN KEY (Reviewer) REFERENCES security.Users(UserId));
CREATE TABLE dbo.ApprovalRequest (RequestId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_ApprovalRequest PRIMARY KEY, ApplicationId UNIQUEIDENTIFIER NOT NULL, RequestedBy UNIQUEIDENTIFIER NOT NULL, SubmittedDate DATETIME2(7) NOT NULL CONSTRAINT DF_ApprovalRequest_Submitted DEFAULT SYSUTCDATETIME(), Status NVARCHAR(32) NOT NULL, CONSTRAINT FK_ApprovalRequest_App FOREIGN KEY (ApplicationId) REFERENCES dbo.Applications(ApplicationId), CONSTRAINT FK_ApprovalRequest_User FOREIGN KEY (RequestedBy) REFERENCES security.Users(UserId));
CREATE TABLE history.ApprovalHistory (ApprovalHistoryId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_ApprovalHistory PRIMARY KEY, RequestId UNIQUEIDENTIFIER NOT NULL, Approver UNIQUEIDENTIFIER NOT NULL, ApprovalLevel NVARCHAR(64) NOT NULL, Decision NVARCHAR(32) NOT NULL, Comment NVARCHAR(MAX) NULL, [Timestamp] DATETIME2(7) NOT NULL CONSTRAINT DF_ApprovalHistory_Timestamp DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_ApprovalHistory_Request FOREIGN KEY (RequestId) REFERENCES dbo.ApprovalRequest(RequestId), CONSTRAINT FK_ApprovalHistory_User FOREIGN KEY (Approver) REFERENCES security.Users(UserId));
CREATE TABLE workflow.WorkflowInstance (WorkflowId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_WorkflowInstance PRIMARY KEY, EntityType NVARCHAR(64) NOT NULL, EntityId UNIQUEIDENTIFIER NOT NULL, CurrentState NVARCHAR(64) NOT NULL, StartedBy UNIQUEIDENTIFIER NOT NULL, StartedDate DATETIME2(7) NOT NULL CONSTRAINT DF_WorkflowInstance_Started DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_WorkflowInstance_User FOREIGN KEY (StartedBy) REFERENCES security.Users(UserId));
CREATE TABLE history.WorkflowHistory (WorkflowHistoryId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_WorkflowHistory PRIMARY KEY, WorkflowId UNIQUEIDENTIFIER NOT NULL, PreviousState NVARCHAR(64) NULL, NewState NVARCHAR(64) NOT NULL, Action NVARCHAR(64) NOT NULL, PerformedBy UNIQUEIDENTIFIER NOT NULL, Reason NVARCHAR(MAX) NULL, [Timestamp] DATETIME2(7) NOT NULL CONSTRAINT DF_WorkflowHistory_Timestamp DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_WorkflowHistory_Workflow FOREIGN KEY (WorkflowId) REFERENCES workflow.WorkflowInstance(WorkflowId), CONSTRAINT FK_WorkflowHistory_User FOREIGN KEY (PerformedBy) REFERENCES security.Users(UserId));
CREATE TABLE security.RiskAcceptance (RiskAcceptanceId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_RiskAcceptance PRIMARY KEY, FindingId UNIQUEIDENTIFIER NOT NULL, RequestedBy UNIQUEIDENTIFIER NOT NULL, ApprovedBy UNIQUEIDENTIFIER NULL, Justification NVARCHAR(MAX) NOT NULL, ExpiryDate DATE NOT NULL, Status NVARCHAR(32) NOT NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_RiskAcceptance_Created DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_RiskAcceptance_Finding FOREIGN KEY (FindingId) REFERENCES dbo.Finding(FindingId));
CREATE TABLE compliance.PolicyException (PolicyExceptionId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_PolicyException PRIMARY KEY, ApplicationId UNIQUEIDENTIFIER NOT NULL, PolicyCode NVARCHAR(128) NOT NULL, Justification NVARCHAR(MAX) NOT NULL, Status NVARCHAR(32) NOT NULL, ExpiresDate DATE NULL, CreatedBy UNIQUEIDENTIFIER NOT NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_PolicyException_Created DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_PolicyException_App FOREIGN KEY (ApplicationId) REFERENCES dbo.Applications(ApplicationId));
CREATE TABLE compliance.ComplianceControl (ControlId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_ComplianceControl PRIMARY KEY, ControlCode NVARCHAR(128) NOT NULL, ControlName NVARCHAR(512) NOT NULL, Framework NVARCHAR(128) NOT NULL, Description NVARCHAR(MAX) NULL, IsActive BIT NOT NULL CONSTRAINT DF_ComplianceControl_Active DEFAULT 1, CONSTRAINT UQ_ComplianceControl_Code UNIQUE (Framework, ControlCode));
CREATE TABLE compliance.ComplianceAssessment (AssessmentId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_ComplianceAssessment PRIMARY KEY, ControlId UNIQUEIDENTIFIER NOT NULL, ApplicationId UNIQUEIDENTIFIER NOT NULL, AssessedBy UNIQUEIDENTIFIER NOT NULL, Result NVARCHAR(32) NOT NULL, EvidenceJson NVARCHAR(MAX) NULL, AssessedDate DATETIME2(7) NOT NULL CONSTRAINT DF_ComplianceAssessment_Date DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_ComplianceAssessment_Control FOREIGN KEY (ControlId) REFERENCES compliance.ComplianceControl(ControlId), CONSTRAINT FK_ComplianceAssessment_App FOREIGN KEY (ApplicationId) REFERENCES dbo.Applications(ApplicationId));
CREATE TABLE dbo.UserActivity (ActivityId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_UserActivity PRIMARY KEY, UserId UNIQUEIDENTIFIER NOT NULL, ActivityType NVARCHAR(128) NOT NULL, EntityType NVARCHAR(64) NULL, EntityId UNIQUEIDENTIFIER NULL, DetailsJson NVARCHAR(MAX) NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_UserActivity_Created DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_UserActivity_User FOREIGN KEY (UserId) REFERENCES security.Users(UserId));
CREATE TABLE dbo.SystemActivity (ActivityId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_SystemActivity PRIMARY KEY, ActivityType NVARCHAR(128) NOT NULL, EntityType NVARCHAR(64) NULL, EntityId UNIQUEIDENTIFIER NULL, DetailsJson NVARCHAR(MAX) NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_SystemActivity_Created DEFAULT SYSUTCDATETIME());
CREATE TABLE dbo.Notification (NotificationId UNIQUEIDENTIFIER NOT NULL CONSTRAINT PK_Notification PRIMARY KEY, UserId UNIQUEIDENTIFIER NOT NULL, NotificationType NVARCHAR(64) NOT NULL, Message NVARCHAR(MAX) NOT NULL, ReadDate DATETIME2(7) NULL, CreatedDate DATETIME2(7) NOT NULL CONSTRAINT DF_Notification_Created DEFAULT SYSUTCDATETIME(), CONSTRAINT FK_Notification_User FOREIGN KEY (UserId) REFERENCES security.Users(UserId));
CREATE TABLE audit.AuditLog (AuditId BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY, EntityType NVARCHAR(128) NOT NULL, EntityId NVARCHAR(128) NULL, ActionType NVARCHAR(64) NOT NULL, PreviousValue NVARCHAR(MAX) NULL, NewValue NVARCHAR(MAX) NULL, UserId UNIQUEIDENTIFIER NULL, UserName NVARCHAR(256) NULL, SessionId NVARCHAR(256) NULL, IPAddress NVARCHAR(64) NULL, Browser NVARCHAR(1024) NULL, [Timestamp] DATETIME2(7) NOT NULL CONSTRAINT DF_AuditLog_Timestamp DEFAULT SYSUTCDATETIME(), CONSTRAINT CK_AuditLog_Action CHECK (ActionType IN (N'CREATE',N'UPDATE',N'DELETE',N'APPROVE',N'REJECT',N'COMMENT',N'MERGE',N'UPLOAD',N'DOWNLOAD',N'EXPORT',N'LOGIN',N'LOGOUT',N'SYSTEM')));
GO

CREATE INDEX IX_Repositories_Application ON dbo.Repositories(ApplicationId, IsDeleted);
CREATE INDEX IX_Finding_Application_Status ON dbo.Finding(ApplicationId, Status, Severity) WHERE IsDeleted = 0;
CREATE INDEX IX_Finding_Repository ON dbo.Finding(RepositoryId, CreatedDate DESC);
CREATE INDEX IX_AuditLog_EntityTime ON audit.AuditLog(EntityType, EntityId, [Timestamp] DESC);
CREATE INDEX IX_AuditLog_UserTime ON audit.AuditLog(UserId, [Timestamp] DESC);
CREATE INDEX IX_WorkflowHistory_WorkflowTime ON history.WorkflowHistory(WorkflowId, [Timestamp] DESC);
CREATE INDEX IX_PRHistory_PRTime ON history.PullRequestHistory(PRId, [Timestamp] DESC);
GO

CREATE OR ALTER PROCEDURE audit.SetContext
    @UserId NVARCHAR(128) = NULL, @UserName NVARCHAR(256) = NULL, @SessionId NVARCHAR(256) = NULL,
    @IPAddress NVARCHAR(64) = NULL, @Browser NVARCHAR(1024) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sys.sp_set_session_context @key=N'UserId', @value=@UserId;
    EXEC sys.sp_set_session_context @key=N'UserName', @value=@UserName;
    EXEC sys.sp_set_session_context @key=N'SessionId', @value=@SessionId;
    EXEC sys.sp_set_session_context @key=N'IPAddress', @value=@IPAddress;
    EXEC sys.sp_set_session_context @key=N'Browser', @value=@Browser;
END;
GO

CREATE OR ALTER PROCEDURE workflow.AppendTransition
    @WorkflowId UNIQUEIDENTIFIER, @NewState NVARCHAR(64), @Action NVARCHAR(64), @PerformedBy UNIQUEIDENTIFIER, @Reason NVARCHAR(MAX) = NULL
AS
BEGIN
    SET XACT_ABORT ON; SET NOCOUNT ON; BEGIN TRANSACTION;
    DECLARE @PreviousState NVARCHAR(64) = (SELECT CurrentState FROM workflow.WorkflowInstance WHERE WorkflowId=@WorkflowId);
    IF @PreviousState IS NULL THROW 51000, 'Workflow does not exist', 1;
    INSERT history.WorkflowHistory(WorkflowHistoryId,WorkflowId,PreviousState,NewState,Action,PerformedBy,Reason) VALUES(NEWID(),@WorkflowId,@PreviousState,@NewState,@Action,@PerformedBy,@Reason);
    UPDATE workflow.WorkflowInstance SET CurrentState=@NewState WHERE WorkflowId=@WorkflowId;
    COMMIT;
END;
GO

CREATE OR ALTER VIEW audit.vw_UnifiedTimeline AS
SELECT AuditId AS EventId, EntityType, EntityId, ActionType AS EventType, COALESCE(UserName,N'SYSTEM') AS Actor, [Timestamp], PreviousValue, NewValue FROM audit.AuditLog;
GO
CREATE OR ALTER VIEW audit.vw_ApplicationHistory AS
SELECT a.ApplicationId, l.EntityType, l.ActionType, l.UserName, l.[Timestamp], l.PreviousValue, l.NewValue
FROM dbo.Applications a JOIN audit.AuditLog l ON l.EntityType=N'Applications' AND l.EntityId=CONVERT(nvarchar(128),a.ApplicationId);
GO

/* Database-level audit triggers capture row images. Application code must add semantic
   events to the history tables before changing a current-state projection. */
DECLARE @sql nvarchar(max)=N'';
SELECT @sql += N'
CREATE OR ALTER TRIGGER ' + QUOTENAME(s.name) + N'.' + QUOTENAME(N'trg_' + t.name + N'_Audit') + N' ON ' + QUOTENAME(s.name) + N'.' + QUOTENAME(t.name) + N' AFTER INSERT, UPDATE, DELETE AS
BEGIN
  SET NOCOUNT ON;
  INSERT audit.AuditLog(EntityType,EntityId,ActionType,PreviousValue,NewValue,UserId,UserName,SessionId,IPAddress,Browser)
  SELECT N''' + s.name + N'.' + t.name + N''', COALESCE(JSON_VALUE(d.JsonRow,N''$.' + REPLACE(CONVERT(nvarchar(128),c.name),'''','''''') + N'''), JSON_VALUE(i.JsonRow,N''$.' + REPLACE(CONVERT(nvarchar(128),c.name),'''','''''') + N''')), CASE WHEN d.JsonRow IS NULL THEN N''CREATE'' WHEN i.JsonRow IS NULL THEN N''DELETE'' ELSE N''UPDATE'' END, d.JsonRow, i.JsonRow,
    TRY_CONVERT(uniqueidentifier,SESSION_CONTEXT(N''UserId'')), CONVERT(nvarchar(256),SESSION_CONTEXT(N''UserName'')), CONVERT(nvarchar(256),SESSION_CONTEXT(N''SessionId'')), CONVERT(nvarchar(64),SESSION_CONTEXT(N''IPAddress'')), CONVERT(nvarchar(1024),SESSION_CONTEXT(N''Browser''))
  FROM (SELECT (SELECT d.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) JsonRow FROM deleted d) d
  FULL OUTER JOIN (SELECT (SELECT i.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) JsonRow FROM inserted i) i ON 1=1;
END;'
FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id
CROSS APPLY (SELECT TOP 1 c.name FROM sys.columns c WHERE c.object_id=t.object_id AND c.is_identity=0 ORDER BY c.column_id) c
WHERE s.name IN (N'dbo',N'security',N'workflow',N'compliance') AND t.name NOT IN (N'AuditLog');
EXEC sys.sp_executesql @sql;
GO

CREATE OR ALTER PROCEDURE audit.AppendEvent
    @EntityType NVARCHAR(128), @EntityId NVARCHAR(128), @ActionType NVARCHAR(64), @PreviousValue NVARCHAR(MAX)=NULL, @NewValue NVARCHAR(MAX)=NULL
AS
BEGIN
    SET NOCOUNT ON;
    INSERT audit.AuditLog(EntityType,EntityId,ActionType,PreviousValue,NewValue,UserId,UserName,SessionId,IPAddress,Browser)
    VALUES(@EntityType,@EntityId,@ActionType,@PreviousValue,@NewValue,TRY_CONVERT(uniqueidentifier,SESSION_CONTEXT(N'UserId')),CONVERT(nvarchar(256),SESSION_CONTEXT(N'UserName')),CONVERT(nvarchar(256),SESSION_CONTEXT(N'SessionId')),CONVERT(nvarchar(64),SESSION_CONTEXT(N'IPAddress')),CONVERT(nvarchar(1024),SESSION_CONTEXT(N'Browser')));
END;
GO

/* Runtime immutability guard. Grant the application role EXECUTE on the
   append procedures and SELECT on history/audit; do not grant direct DML. */
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name=N'SecurityGovernanceRuntime')
    CREATE ROLE SecurityGovernanceRuntime;
DENY UPDATE, DELETE ON SCHEMA::audit TO SecurityGovernanceRuntime;
DENY UPDATE, DELETE ON SCHEMA::history TO SecurityGovernanceRuntime;
DENY UPDATE, DELETE ON OBJECT::audit.AuditLog TO SecurityGovernanceRuntime;
GRANT SELECT ON SCHEMA::audit TO SecurityGovernanceRuntime;
GRANT SELECT ON SCHEMA::history TO SecurityGovernanceRuntime;
GRANT EXECUTE ON OBJECT::audit.SetContext TO SecurityGovernanceRuntime;
GRANT EXECUTE ON OBJECT::audit.AppendEvent TO SecurityGovernanceRuntime;
GRANT EXECUTE ON OBJECT::workflow.AppendTransition TO SecurityGovernanceRuntime;
GO

CREATE OR ALTER TRIGGER audit.trg_AuditLog_Immutable ON audit.AuditLog
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    THROW 51001, 'AuditLog is immutable; append a compensating event instead.', 1;
END;
GO