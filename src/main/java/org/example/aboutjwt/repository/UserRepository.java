package org.example.aboutjwt.repository;

import java.util.List;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.example.aboutjwt.domain.User;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class UserRepository {

    private final EntityManager em;

    public void save(User user) {
        em.persist(user);
    }

    public User findByName(String name) {
        String query = "SELECT u FROM User u WHERE u.name = :name";
        List<User> foundUser = em.createQuery(query, User.class).setParameter("name", name).getResultList();

        return foundUser.isEmpty() ? null : foundUser.get(0);
    }

}
