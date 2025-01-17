package org.chhan.ex_jwt.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.chhan.ex_jwt.domain.User;
import org.chhan.ex_jwt.domain.querydsl.QUser;
import org.springframework.stereotype.Repository;

@Slf4j
@Repository
@RequiredArgsConstructor
public class UserRepositoryCustomImpl implements UserRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public User findByEmail(String email) {
        return queryFactory.selectFrom(QUser.user)
                .where(QUser.user.email.eq(email))
                .fetchOne();
    }

    @Override
    public User findByUserId(Long id) {
        return queryFactory.selectFrom(QUser.user)
                .where(QUser.user.id.eq(id))
                .fetchOne();
    }

    @Transactional
    @Override
    public void updateUserRefreshToken(User user) {
        QUser qUser = QUser.user;

        queryFactory.update(qUser)
                .set(qUser.currentRefreshToken, user.getCurrentRefreshToken())
                .where(qUser.id.eq(user.getId()))
                .execute();
    }

    @Transactional
    @Override
    public long logOut(long id) {
        return queryFactory.update(QUser.user)
                .set(QUser.user.currentRefreshToken, (String) null)
                .where(QUser.user.id.eq(id))
                .execute();
    }
}
