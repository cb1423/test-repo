package smartify

import grails.gorm.transactions.Transactional
import groovy.time.TimeCategory
import org.apache.commons.lang.RandomStringUtils
import org.springframework.dao.DuplicateKeyException
import smartify.entity.UserStatus
import smartify.exception.AuthenticationException
import smartify.web.response.Token
import spotify.ApiService
import spotify.Profile

@Transactional
class UserService {

    SmartPlaylistService smartPlaylistService
    RecordService recordService
    UserInfoService userInfoServiceProxy
    ApiService apiService

    User getUser(String userId) {
        return User.findByUsername(userId)
    }

    User getCurrentUser() {
        return User.findByUsername(userInfoServiceProxy.id)
    }

    Collection<User> getUsers() {
        return User.findAllByStatusInList([UserStatus.ACTIVE, UserStatus.INACTIVE])
    }

    Collection<User> getActiveUsers() {
        return User.findAllByStatus(UserStatus.ACTIVE)
    }

    Collection<User> getInactiveUsers() {
        return User.findAllByStatus(UserStatus.INACTIVE)
    }

    User getOrCreateUser(Profile profile, Authentication authentication) {
        User user
        if (getUser(profile.id)) {
            user = getUser(profile.id)
            setAuthentication(user, authentication)
        } else {
            user = createUser(profile)
            setAuthentication(user, authentication)

            // TODO Only for development, remove before production
            smartPlaylistService.importFromSpotify(user)
            smartPlaylistService.deleteAllSmartPlaylists(user)
            // TODO Only for development, remove before production

            smartPlaylistService.createDefaultSmartPlaylists(user)
        }
        user.save(flush: true)
        return user
    }

    User createUser(Profile profile) {
        User user = new User(profile)
        user.save(flush: true)
        log.info "Account created for $user.username:$user.displayName"
        return user
    }

    Profile getProfile(String accessToken) {
        return apiService.getProfile(accessToken)
    }

    void logon(User user) {
        user.status = UserStatus.ACTIVE
        user.lastChanged = new Date()
        user.save(flush: true)
        userInfoServiceProxy.id = user.id
        log.info "${user?.displayName} has logged on"
    }

    void logoff(User user) {
        userInfoServiceProxy.id = null
        log.info "${user?.displayName} has logged off"
    }

    void deactivate(User user) {
        user.status = UserStatus.DEACTIVATED
        user.lastRecorded?.delete()
        user.currentlyPlaying?.delete()
        user.lastRecorded = null
        user.currentlyPlaying = null
        user.save(flush: true)
        log.info "${user?.displayName} has deactivated their account"
    }

    void reactivate(User user) {
        user.status = UserStatus.ACTIVE
        user.lastChanged = new Date()
        user.save(flush: true)
        log.info "${user?.displayName} has reactivated their account"
    }

    void delete(User user) {
        List<SmartPlaylist> playlists = SmartPlaylist.findAllByUser(user)
        List<TrackHistory> history = TrackHistory.findAllByUser(user)

        playlists.each { playlist ->
            smartPlaylistService.deleteSmartPlaylist(user, playlist.id)
        }

        TrackHistory.deleteAll(history)

        LastRecorded.findByUser(user)?.delete()
        CurrentlyPlaying.findByUser(user)?.delete()
        Authentication.findByUser(user)?.delete()
        user.delete(flush: true)
        log.info "${user?.displayName} deleted their account"
    }

    Authentication getAuthentication(String code, String state) {
        if (state != this.state && state != null) {
            throw new AuthenticationException('Invalid state', 'The server did not return the same state that it was supplied with')
        }
        log.debug("Authorisation code: $code")
        log.debug("state received: $state")
        this.state = null
        Token token = apiService.getToken(code)
        return token.authentication
    }

    void setAuthentication(User user, Authentication authentication) {
        Authentication auth = Authentication.findOrCreateByUser(user)
        auth.with {
            accessToken = authentication.accessToken
            refreshToken = authentication.refreshToken
            expiry = authentication.expiry
        }
        auth.user = user
        user.authentication = auth
        user.save(flush: true)
    }

    void renewAuthentication(User user) {
        Token token = apiService.refreshToken(user)
        use(TimeCategory) {
            user.authentication.with {
                accessToken = token.accessToken
                expiry = new Date() + token.expiresIn.milliseconds
            }
        }
        user.save(flush: true)
        log.debug("Access token refreshed for $user.username")
    }

    TrackHistory getHistoryOfCurrentlyPlaying(User user) {
        CurrentlyPlaying playing = CurrentlyPlaying.findByUser(user)
        return TrackHistory.findByTrack(playing?.track) ?: new TrackHistory(track: playing?.track)
    }

    void updateCurrentlyPlaying(User user) {
        CurrentlyPlaying playing = apiService.getPlaying(user)
        user.lastPoll = new Date()

        setCurrentlyPlaying(user, playing)
        user.logCurrentlyPlaying()
        setPollingDate(user)

        try {
            user.save(flush: true)
        } catch (DuplicateKeyException ignored) {}
    }

    void setCurrentlyPlaying(User user, CurrentlyPlaying playing) {
        if (!playing?.track) {
            user.currentlyPlaying?.delete()
            user.currentlyPlaying = null
            user.status = UserStatus.INACTIVE
            return
        } else if (user.currentlyPlaying?.isReset(playing)) {
            user.lastRecorded?.delete()
            user.lastRecorded = null
        } else if (user.currentlyPlaying != playing) {
            user.lastChanged = new Date()
            user.status = UserStatus.ACTIVE
        }

        user.currentlyPlaying = user.currentlyPlaying ?: new CurrentlyPlaying(user: user)

        user.currentlyPlaying.track = recordService.updateTrack(playing?.track)
        user.currentlyPlaying.progress = playing.progress
    }

    void setActive(User user) {
        user.status = UserStatus.ACTIVE
        user.save(flush: true)
        log.debug "$user.displayName is active"
    }

    void setInactive(User user) {
        user.status = UserStatus.INACTIVE
        user.save(flush: true)
        log.debug "$user.displayName is inactive"
    }

    String getState() {
        return userInfoServiceProxy.state
    }

    void setNewState() {
        setState(RandomStringUtils.random(24, true, true))
    }

    void setPercentage(User user, Integer percentage) {
        user.percentage = percentage
        user.save(flush: true)
        log.info "${user?.displayName} set their recording threshold to ${user?.percentage}%"
    }

    void setPollingDate(User user) {
        use (TimeCategory) {
            if (user.currentlyPlaying?.withinPollingPeriod) {
                user.nextPoll = user.currentlyPlaying.nextPoll
            } else {
                if (user.active) {
                    user.nextPoll = new Date() + SmartifyConfig.pollActiveUsers.seconds
                } else {
                    user.nextPoll = new Date() + SmartifyConfig.pollInactiveUsers.seconds
                }
            }
            log.debug "Poll at ${user.nextPoll.format('HH:mm:ss.SSS')}"
        }
    }

    private void setState(String state) {
        userInfoServiceProxy.state = state
    }
}