interface Props {
    avatarUrl: string;
    /** Shows a dot: something in the profile needs the user (the key backup). */
    attention?: boolean;
    onClick: () => void;
}

export function AvatarView({ avatarUrl, attention = false, onClick }: Props) {
    return (
        <div
            id="view-avatar"
            className="view active"
            role="button"
            tabIndex={0}
            aria-label={attention ? 'Open Nostr profile (key not backed up)' : 'Open Nostr profile'}
            onClick={onClick}
            onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onClick();
                }
            }}
        >
            <img id="avatar-img" src={avatarUrl} alt="Profile avatar" />
            {attention && <span className="avatar-dot" aria-hidden="true" />}
        </div>
    );
}
