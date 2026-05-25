interface Props {
    avatarUrl: string;
    onClick: () => void;
}

export function AvatarView({ avatarUrl, onClick }: Props) {
    return (
        <div
            id="view-avatar"
            className="view active"
            role="button"
            tabIndex={0}
            aria-label="Open Nostr profile"
            onClick={onClick}
            onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onClick();
                }
            }}
        >
            <img id="avatar-img" src={avatarUrl} alt="Profile avatar" />
        </div>
    );
}
