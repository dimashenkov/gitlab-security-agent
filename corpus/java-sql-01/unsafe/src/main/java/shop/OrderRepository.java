package shop;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;

@Repository
public class OrderRepository {

    @PersistenceContext
    EntityManager em;

    public long countAll() {
        return (Long) em.createQuery("SELECT count(o) FROM Order o").getSingleResult();
    }
}
