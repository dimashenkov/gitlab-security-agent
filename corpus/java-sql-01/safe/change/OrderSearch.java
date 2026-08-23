package shop;

import java.util.List;
import javax.persistence.TypedQuery;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderSearch {

    private final OrderRepository repository;

    OrderSearch(OrderRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/orders/search")
    public List<Order> byStatus(@RequestParam String status) {
        TypedQuery<Order> query = repository.em.createQuery(
                "SELECT o FROM Order o WHERE o.status = :status", Order.class);
        query.setParameter("status", status);
        return query.getResultList();
    }
}
